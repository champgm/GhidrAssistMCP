/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool to remove a field from a Structure by field name or offset.
 */
public class RemoveStructureFieldTool implements McpTool {
	@Override
	public String getName() {
		return "remove_structure_field";
	}

	@Override
	public String getDescription() {
		return "Remove a field from a structure by name or by byte offset";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"structure_path", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"offset", new McpSchema.JsonSchema("number", null, null, null, null, null),
				"delete_resizes", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
			),
			List.of("structure_path"), null, null, null);
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
		Number offsetNum = (Number) arguments.get("offset");
		Boolean deleteResizes = (Boolean) arguments.get("delete_resizes");

		if (structurePathStr == null || structurePathStr.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'structure_path' is required, e.g. '/MyCategory/MyStruct'")
				.build();
		}

		if ((fieldName == null || fieldName.isEmpty()) && offsetNum == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("Provide either 'field_name' or 'offset'")
				.build();
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		Structure structure = findStructureByPath(dtm, structurePathStr);
		if (structure == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("Structure not found: " + structurePathStr)
				.build();
		}

		int tx = currentProgram.startTransaction("Remove Structure Field");
		boolean commit = false;
		try {
			String actionMsg;
			if (offsetNum != null) {
				int offset = offsetNum.intValue();
				if (deleteResizes != null && deleteResizes.booleanValue()) {
					structure.deleteAtOffset(offset);
					actionMsg = "deleted component containing offset " + offset;
				} else {
					structure.clearAtOffset(offset);
					actionMsg = "cleared component(s) at offset " + offset;
				}
			} else {
				// by name: find first component with matching field name
				DataTypeComponent[] comps = structure.getDefinedComponents();
				DataTypeComponent target = null;
				for (DataTypeComponent c : comps) {
					if (fieldName.equals(c.getFieldName())) {
						target = c;
						break;
					}
				}
				if (target == null) {
					return McpSchema.CallToolResult.builder()
						.addTextContent("Field not found by name: " + fieldName)
						.build();
				}
				int off = target.getOffset();
				if (deleteResizes != null && deleteResizes.booleanValue()) {
					structure.deleteAtOffset(off);
				} else {
					structure.clearAtOffset(off);
				}
				actionMsg = "removed field '" + fieldName + "' at offset " + off;
			}

			commit = true;
			return McpSchema.CallToolResult.builder()
				.addTextContent("Successfully " + actionMsg + " in '" + structure.getName() + "'")
				.build();
		} catch (Exception e) {
			Msg.error(this, "Failed to remove structure field", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Failed to remove field: " + e.getMessage())
				.build();
		} finally {
			currentProgram.endTransaction(tx, commit);
		}
	}

	private Structure findStructureByPath(DataTypeManager dtm, String fullPath) {
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
}
