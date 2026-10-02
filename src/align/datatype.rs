//! DataType alignment verification logic.
//!
//! This module ensures that Rudra's type system matches Ghidra's
//! internal Datatype representation as defined in `type.hh`.

use crate::types::{DataType, StructDef, FieldDef};

// RUDRA-GLUE: verify_datatype (no Ghidra counterpart found)
/// Verify that a Rudra DataType aligns with Ghidra's representation
///
/// Checks size and metatype compatibility
pub fn verify_datatype(
    rudra_type: &DataType,
    ghidra_name: &str,
    ghidra_size: usize,
    ghidra_metatype: &str,
) -> bool {
    let size_match = rudra_type.size() == ghidra_size;

    // Verify metatype compatibility
    let metatype_match = match (rudra_type, ghidra_metatype) {
        (DataType::Pointer(..), "ptr") => true,
        (DataType::Array(..), "array") => true,
        (DataType::Struct(_), "struct") => true,
        (DataType::Int(..), "int") => true,
        (DataType::Float(_), "float") => true,
        (DataType::Bool, "bool") => true,
        (DataType::Void, "void") => true,
        (DataType::Unknown(_), _) => true, // Unknown can match anything
        _ => false,
    };

    if !size_match {
        eprintln!(
            "[ALIGN DIFF] DataType size mismatch: Ghidra '{}' size {}, Rudra size {}",
            ghidra_name,
            ghidra_size,
            rudra_type.size()
        );
    }

    if !metatype_match {
        eprintln!(
            "[ALIGN DIFF] DataType metatype mismatch: Ghidra '{}' type '{}', Rudra {:?}",
            ghidra_name,
            ghidra_metatype,
            rudra_type
        );
    }

    size_match && metatype_match
}

// RUDRA-GLUE: verify_struct_layout (no Ghidra counterpart found)
/// Verify struct layout alignment
///
/// Checks that field offsets and sizes match between Rudra and Ghidra
pub fn verify_struct_layout(
    rudra_struct: &StructDef,
    ghidra_name: &str,
    ghidra_fields: &[(String, usize, usize)], // (name, offset, size)
) -> bool {
    if rudra_struct.name != ghidra_name {
        eprintln!(
            "[ALIGN DIFF] Struct name mismatch: Rudra '{}' != Ghidra '{}'",
            rudra_struct.name,
            ghidra_name
        );
        return false;
    }

    if rudra_struct.fields.len() != ghidra_fields.len() {
        eprintln!(
            "[ALIGN DIFF] Struct '{}' field count mismatch: Rudra {} != Ghidra {}",
            ghidra_name,
            rudra_struct.fields.len(),
            ghidra_fields.len()
        );
        return false;
    }

    // Verify each field
    for (rudra_field, (ghidra_name, ghidra_offset, ghidra_size)) in
        rudra_struct.fields.iter().zip(ghidra_fields.iter()) {

        if rudra_field.name != *ghidra_name {
            eprintln!(
                "[ALIGN DIFF] Field name mismatch in struct '{}': Rudra '{}' != Ghidra '{}'",
                rudra_struct.name,
                rudra_field.name,
                ghidra_name
            );
            return false;
        }

        if rudra_field.offset != *ghidra_offset {
            eprintln!(
                "[ALIGN DIFF] Field '{}' offset mismatch in struct '{}': Rudra {} != Ghidra {}",
                rudra_field.name,
                rudra_struct.name,
                rudra_field.offset,
                ghidra_offset
            );
            return false;
        }

        let rudra_size = rudra_field.data_type.size();
        if rudra_size != *ghidra_size {
            eprintln!(
                "[ALIGN DIFF] Field '{}' size mismatch in struct '{}': Rudra {} != Ghidra {}",
                rudra_field.name,
                rudra_struct.name,
                rudra_size,
                ghidra_size
            );
            return false;
        }
    }

    true
}

// RUDRA-GLUE: verify_field (no Ghidra counterpart found)
/// Verify field definition alignment
pub fn verify_field(
    rudra_field: &FieldDef,
    ghidra_name: &str,
    ghidra_offset: usize,
    ghidra_size: usize,
) -> bool {
    let name_match = rudra_field.name == ghidra_name;
    let offset_match = rudra_field.offset == ghidra_offset;
    let size_match = rudra_field.data_type.size() == ghidra_size;

    if !name_match {
        eprintln!(
            "[ALIGN DIFF] Field name mismatch: Rudra '{}' != Ghidra '{}'",
            rudra_field.name,
            ghidra_name
        );
    }

    if !offset_match {
        eprintln!(
            "[ALIGN DIFF] Field '{}' offset mismatch: Rudra {} != Ghidra {}",
            rudra_field.name,
            rudra_field.offset,
            ghidra_offset
        );
    }

    if !size_match {
        eprintln!(
            "[ALIGN DIFF] Field '{}' size mismatch: Rudra {} != Ghidra {}",
            rudra_field.name,
            rudra_field.data_type.size(),
            ghidra_size
        );
    }

    name_match && offset_match && size_match
}

// RUDRA-GLUE: verify_pointer_type (no Ghidra counterpart found)
/// Verify pointer type alignment
pub fn verify_pointer_type(
    rudra_type: &DataType,
    _ghidra_pointee_size: usize,
    ghidra_ptr_size: usize,
) -> bool {
    match rudra_type {
        DataType::Pointer { .. } => {
            let size_match = rudra_type.size() == ghidra_ptr_size;
            if !size_match {
                eprintln!(
                    "[ALIGN DIFF] Pointer size mismatch: Rudra {} != Ghidra {}",
                    rudra_type.size(),
                    ghidra_ptr_size
                );
            }
            size_match
        }
        _ => {
            eprintln!("[ALIGN DIFF] Expected pointer type, got {:?}", rudra_type);
            false
        }
    }
}

// RUDRA-GLUE: verify_array_type (no Ghidra counterpart found)
/// Verify array type alignment
pub fn verify_array_type(
    rudra_type: &DataType,
    _ghidra_element_size: usize,
    _ghidra_element_count: usize,
    ghidra_total_size: usize,
) -> bool {
    match rudra_type {
        DataType::Array { .. } => {
            let size_match = rudra_type.size() == ghidra_total_size;
            if !size_match {
                eprintln!(
                    "[ALIGN DIFF] Array size mismatch: Rudra {} != Ghidra {}",
                    rudra_type.size(),
                    ghidra_total_size
                );
            }
            size_match
        }
        _ => {
            eprintln!("[ALIGN DIFF] Expected array type, got {:?}", rudra_type);
            false
        }
    }
}

// RUDRA-GLUE: verify_primitive_size (no Ghidra counterpart found)
/// Verify primitive type size alignment
pub fn verify_primitive_size(rudra_type: &DataType, ghidra_size: usize) -> bool {
    let size_match = rudra_type.size() == ghidra_size;
    if !size_match {
        eprintln!(
            "[ALIGN DIFF] Primitive type size mismatch: Rudra {:?} (size {}) != Ghidra size {}",
            rudra_type,
            rudra_type.size(),
            ghidra_size
        );
    }
    size_match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_primitive_types() {
        assert!(verify_datatype(&DataType::Int(4, true), "int", 4, "int"));
        assert!(verify_datatype(&DataType::Float(4), "float", 4, "float"));
        assert!(verify_datatype(&DataType::Bool, "bool", 1, "bool"));
        assert!(verify_datatype(&DataType::Void, "void", 0, "void"));
    }

    #[test]
    fn test_verify_primitive_size() {
        assert!(verify_primitive_size(&DataType::Int(4, true), 4));
        assert!(verify_primitive_size(&DataType::Float(8), 8));
        assert!(!verify_primitive_size(&DataType::Int(4, true), 8));
    }

    #[test]
    fn test_verify_pointer_type() {
        let ptr_type = DataType::Pointer(
            Box::new(DataType::Int(4, true)),
            8
        );
        assert!(verify_pointer_type(&ptr_type, 4, 8));
        assert!(!verify_pointer_type(&ptr_type, 4, 4));
    }

    #[test]
    fn test_verify_field() {
        let field = FieldDef {
            name: "x".to_string(),
            data_type: DataType::Int(4, true),
            offset: 0,
        };

        assert!(verify_field(&field, "x", 0, 4));
        assert!(!verify_field(&field, "y", 0, 4));
        assert!(!verify_field(&field, "x", 4, 4));
        assert!(!verify_field(&field, "x", 0, 8));
    }

    #[test]
    fn test_verify_struct_layout() {
        let rudra_struct = StructDef {
            name: "Point".to_string(),
            fields: vec![
                FieldDef {
                    name: "x".to_string(),
                    data_type: DataType::Int(4, true),
                    offset: 0,
                },
                FieldDef {
                    name: "y".to_string(),
                    data_type: DataType::Int(4, true),
                    offset: 4,
                },
            ],
        };

        let ghidra_fields = vec![
            ("x".to_string(), 0, 4),
            ("y".to_string(), 4, 4),
        ];

        assert!(verify_struct_layout(&rudra_struct, "Point", &ghidra_fields));
    }

    #[test]
    fn test_verify_struct_layout_mismatch() {
        let rudra_struct = StructDef {
            name: "Point".to_string(),
            fields: vec![
                FieldDef {
                    name: "x".to_string(),
                    data_type: DataType::Int(4, true),
                    offset: 0,
                },
            ],
        };

        let ghidra_fields = vec![
            ("x".to_string(), 0, 4),
            ("y".to_string(), 4, 4), // Extra field in Ghidra
        ];

        assert!(!verify_struct_layout(&rudra_struct, "Point", &ghidra_fields));
    }
}
