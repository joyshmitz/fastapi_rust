//! JSON Schema types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JSON Schema representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Schema {
    /// Boolean schema (true = any, false = none).
    Boolean(bool),
    /// Reference to another schema.
    Ref(RefSchema),
    /// Object schema.
    Object(ObjectSchema),
    /// Array schema.
    Array(ArraySchema),
    /// Primitive type schema.
    Primitive(PrimitiveSchema),
}

/// Schema reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefSchema {
    /// Reference path (e.g., "#/components/schemas/Item").
    #[serde(rename = "$ref")]
    pub reference: String,
}

/// Object schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectSchema {
    /// Object properties.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, Schema>,
    /// Required property names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Additional properties schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<Box<Schema>>,
}

/// Array schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArraySchema {
    /// Item schema.
    pub items: Box<Schema>,
    /// Minimum items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<usize>,
    /// Maximum items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<usize>,
}

/// Primitive type schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveSchema {
    /// JSON Schema type.
    #[serde(rename = "type")]
    pub schema_type: SchemaType,
    /// Format hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Nullable flag (OpenAPI 3.1).
    #[serde(default, skip_serializing_if = "is_false")]
    pub nullable: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// JSON Schema primitive types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    /// String type.
    String,
    /// Number type (float).
    Number,
    /// Integer type.
    Integer,
    /// Boolean type.
    Boolean,
    /// Null type.
    Null,
}

/// Trait for types that can generate JSON Schema.
pub trait JsonSchema {
    /// Generate the JSON Schema for this type.
    fn schema() -> Schema;

    /// Get the schema name for use in `#/components/schemas/`.
    fn schema_name() -> Option<&'static str> {
        None
    }
}

// Implement for primitive types
impl JsonSchema for String {
    fn schema() -> Schema {
        Schema::Primitive(PrimitiveSchema {
            schema_type: SchemaType::String,
            format: None,
            nullable: false,
        })
    }
}

impl JsonSchema for i64 {
    fn schema() -> Schema {
        Schema::Primitive(PrimitiveSchema {
            schema_type: SchemaType::Integer,
            format: Some("int64".to_string()),
            nullable: false,
        })
    }
}

impl JsonSchema for i32 {
    fn schema() -> Schema {
        Schema::Primitive(PrimitiveSchema {
            schema_type: SchemaType::Integer,
            format: Some("int32".to_string()),
            nullable: false,
        })
    }
}

impl JsonSchema for f64 {
    fn schema() -> Schema {
        Schema::Primitive(PrimitiveSchema {
            schema_type: SchemaType::Number,
            format: Some("double".to_string()),
            nullable: false,
        })
    }
}

impl JsonSchema for bool {
    fn schema() -> Schema {
        Schema::Primitive(PrimitiveSchema {
            schema_type: SchemaType::Boolean,
            format: None,
            nullable: false,
        })
    }
}

impl<T: JsonSchema> JsonSchema for Option<T> {
    fn schema() -> Schema {
        match T::schema() {
            Schema::Primitive(mut p) => {
                p.nullable = true;
                Schema::Primitive(p)
            }
            other => other,
        }
    }
}

impl<T: JsonSchema> JsonSchema for Vec<T> {
    fn schema() -> Schema {
        Schema::Array(ArraySchema {
            items: Box::new(T::schema()),
            min_items: None,
            max_items: None,
        })
    }
}
