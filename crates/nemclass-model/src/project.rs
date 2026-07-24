use std::collections::HashMap;

use uuid::Uuid;

use crate::class::{children_reference_class, ClassNode};
use crate::enums::EnumDescription;
use crate::error::{ModelError, Result};
use crate::node::registry::NodeRegistry;
use crate::serialize::{ClassDef, EnumDef, EnumValueDef, ProjectFile, ProjectMeta};

pub struct Project {
    pub name: String,
    classes: HashMap<Uuid, ClassNode>,
    class_order: Vec<Uuid>,
    pub enums: Vec<EnumDescription>,
}

impl Project {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            classes: HashMap::new(),
            class_order: Vec::new(),
            enums: Vec::new(),
        }
    }

    pub fn add_class(&mut self, class: ClassNode) {
        let uuid = class.uuid;
        if !self.classes.contains_key(&uuid) {
            self.class_order.push(uuid);
        }
        self.classes.insert(uuid, class);
    }

    pub fn get_class(&self, uuid: &Uuid) -> Option<&ClassNode> {
        self.classes.get(uuid)
    }

    pub fn get_class_mut(&mut self, uuid: &Uuid) -> Option<&mut ClassNode> {
        self.classes.get_mut(uuid)
    }

    pub fn classes_in_order(&self) -> impl Iterator<Item = &ClassNode> {
        self.class_order.iter().filter_map(|id| self.classes.get(id))
    }

    /// Remove a class, returning `ClassReferenced` error if any other class references it.
    pub fn remove_class(&mut self, uuid: &Uuid) -> Result<ClassNode> {
        let class = self.classes.get(uuid).ok_or(ModelError::ClassNotFound(*uuid))?;
        let class_name = class.name.clone();

        let ref_count = self.classes.iter()
            .filter(|(id, _)| *id != uuid)
            .filter(|(_, c)| children_reference_class(&c.children, uuid))
            .count();

        if ref_count > 0 {
            return Err(ModelError::ClassReferenced { name: class_name, ref_count });
        }

        self.class_order.retain(|id| id != uuid);
        Ok(self.classes.remove(uuid).unwrap())
    }

    pub fn to_toml(&self, registry: &NodeRegistry) -> Result<String> {
        let classes = self.class_order.iter()
            .filter_map(|id| self.classes.get(id))
            .map(|class| {
                let nodes = class.children.iter()
                    .map(|n| registry.serialize_node_recursive(n.as_ref()))
                    .collect();
                ClassDef {
                    uuid: class.uuid.to_string(),
                    name: class.name.clone(),
                    comment: class.comment.clone(),
                    address_formula: class.address_formula.clone(),
                    nodes,
                }
            })
            .collect();

        let enums = self.enums.iter()
            .map(|e| EnumDef {
                name: e.name.clone(),
                size: e.size,
                use_flags: e.use_flags,
                values: e.values.iter()
                    .map(|(name, value)| EnumValueDef { name: name.clone(), value: *value })
                    .collect(),
            })
            .collect();

        let file = ProjectFile {
            project: ProjectMeta {
                name: self.name.clone(),
                version: "1".to_string(),
            },
            enums,
            classes,
        };

        toml::to_string(&file).map_err(|e| ModelError::SerializeError(e.to_string()))
    }

    pub fn from_toml(s: &str, registry: &NodeRegistry) -> Result<Self> {
        let file: ProjectFile = toml::from_str(s)
            .map_err(|e| ModelError::DeserializeError(e.to_string()))?;

        let mut project = Project::new(file.project.name);

        for edef in file.enums {
            project.enums.push(EnumDescription {
                name: edef.name,
                size: edef.size,
                use_flags: edef.use_flags,
                values: edef.values.into_iter().map(|v| (v.name, v.value)).collect(),
            });
        }

        for cdef in file.classes {
            let uuid = cdef.uuid.parse::<Uuid>()
                .map_err(|e| ModelError::DeserializeError(format!("bad class uuid: {e}")))?;
            let mut class = ClassNode::with_uuid(uuid, cdef.name);
            class.comment = cdef.comment;
            class.address_formula = cdef.address_formula;
            for node_def in cdef.nodes {
                class.children.push(registry.deserialize_node(node_def)?);
            }
            project.add_class(class);
        }

        Ok(project)
    }
}
