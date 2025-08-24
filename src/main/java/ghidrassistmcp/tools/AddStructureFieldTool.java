/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that adds a field to an existing Structure data type.
 */
public class AddStructureFieldTool implements McpTool {
	@Override
	public String getName() {
		return "add_structure_field";
	}

	@Override
	public String getDescription() {
		return "Add a field to an existing Structure data type";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"structure_path", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"field_type", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"length", new McpSchema.JsonSchema("number", null, null, null, null, null),
				"is_pointer", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
				"is_array", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
				"array_count", new McpSchema.JsonSchema("number", null, null, null, null, null),
				"offset", new McpSchema.JsonSchema("number", null, null, null, null, null)
			),
			List.of("structure_path", "field_name", "field_type"), null, null, null);
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
		if (currentProgram == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("No program currently loaded")
				.build();
		}

		String structurePathStr = (String) arguments.get("structure_path");
		String fieldName = (String) arguments.get("field_name");
		String fieldTypeStr = (String) arguments.get("field_type");
		Number lengthNum = (Number) arguments.get("length");
		Boolean isPointer = (Boolean) arguments.get("is_pointer");
		Boolean isArray = (Boolean) arguments.get("is_array");
		Number arrayCountNum = (Number) arguments.get("array_count");
		Number offsetNum = (Number) arguments.get("offset");

		if (structurePathStr == null || structurePathStr.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'structure_path' is required, e.g. '/MyCategory/MyStruct'")
				.build();
		}
		if (fieldName == null || fieldName.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'field_name' is required")
				.build();
		}
		if (fieldTypeStr == null || fieldTypeStr.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'field_type' is required")
				.build();
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();

		// Resolve structure
		Structure structure = findStructureByPath(dtm, structurePathStr);
		if (structure == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("Structure not found: " + structurePathStr)
				.build();
		}

		// Resolve field type
		DataType baseType = resolveTypeByName(dtm, fieldTypeStr);
		if (baseType == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("Field type not found: " + fieldTypeStr)
				.build();
		}

		DataType finalType = baseType;
		if (isPointer != null && isPointer.booleanValue()) {
			finalType = new PointerDataType(finalType);
		}
		if (isArray != null && isArray.booleanValue()) {
			int count = arrayCountNum != null ? arrayCountNum.intValue() : 0;
			if (count <= 0) {
				return McpSchema.CallToolResult.builder()
					.addTextContent("'array_count' must be > 0 when is_array is true")
					.build();
			}
			int elemLength = lengthNum != null ? lengthNum.intValue() : finalType.getLength();
			if (elemLength <= 0 && !(finalType instanceof PointerDataType)) {
				return McpSchema.CallToolResult.builder()
					.addTextContent("Provide a positive 'length' for variable-length base types")
					.build();
			}
			finalType = new ArrayDataType(finalType, count, elemLength);
		}

		int tx = currentProgram.startTransaction("Add Structure Field: " + fieldName);
		boolean commit = false;
		try {
			int offset = offsetNum != null ? offsetNum.intValue() : -1;
			if (offset >= 0) {
				structure.replaceAtOffset(offset, finalType, finalType.getLength(), fieldName, null);
			} else {
				structure.add(finalType, fieldName, null);
			}
			// Persist the modified structure
			dtm.replaceDataType(structure, structure, true);
			commit = true;
			return McpSchema.CallToolResult.builder()
				.addTextContent("Added field '" + fieldName + "' of type '" + finalType.getDisplayName() + "' to '" + structure.getName() + "'")
				.build();
		} catch (Exception e) {
			Msg.error(this, "Failed to add structure field", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Failed to add field: " + e.getMessage())
				.build();
		} finally {
			currentProgram.endTransaction(tx, commit);
		}
	}

	private Structure findStructureByPath(DataTypeManager dtm, String fullPath) {
		// Expect input like "/Category/Sub/MyStruct" or just "/MyStruct" or "MyStruct"
		String normalized = fullPath;
		if (normalized.startsWith("/")) {
			normalized = normalized.substring(1);
		}
		int lastSlash = normalized.lastIndexOf('/');
		String category = lastSlash >= 0 ? "/" + normalized.substring(0, lastSlash) : "/";
		String name = lastSlash >= 0 ? normalized.substring(lastSlash + 1) : normalized;
		DataType dt = dtm.getDataType(new CategoryPath(category), name);
		if (dt instanceof Structure) {
			return (Structure) dt;
		}
		return null;
	}

	private DataType resolveTypeByName(DataTypeManager dtm, String name) {
		// Try exact category path form first
		if (name.startsWith("/")) {
			int lastSlash = name.lastIndexOf('/');
			String category = lastSlash > 0 ? name.substring(0, lastSlash) : "/";
			String dtName = lastSlash >= 0 ? name.substring(lastSlash + 1) : name;
			DataType dt = dtm.getDataType(new CategoryPath(category), dtName);
			if (dt != null) {
				return dt;
			}
		}

		// Try by simple name
		DataType dt = dtm.getDataType(name);
		if (dt != null) {
			return dt;
		}


		// Map common built-in type names (case-insensitive)
		String n = name.trim().toLowerCase();
		switch (n) {
			case "void":
				return new VoidDataType();
			case "byte":
			case "int8_t":
			case "i8":
			case "sbyte":
				return new ByteDataType();
			case "char":
				return new CharDataType();
			case "word":
			case "short":
			case "int16_t":
			case "i16":
				return new WordDataType();
			case "dword":
			case "int":
			case "int32_t":
			case "i32":
				return new DWordDataType();
			case "qword":
			case "long":
			case "int64_t":
			case "i64":
				return new QWordDataType();
			case "bool":
			case "boolean":
				return new BooleanDataType();
			case "float":
				return new FloatDataType();
			case "double":
				return new DoubleDataType();
			default:
				break;
		}

		return null;
	}
}
