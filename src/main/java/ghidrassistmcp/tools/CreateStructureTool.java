/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that creates a new empty Structure data type in the current program's Data Type Manager.
 */
public class CreateStructureTool implements McpTool {
	@Override
	public String getName() {
		return "create_structure";
	}

	@Override
	public String getDescription() {
		return "Create an empty Structure data type in the Data Type Manager";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"name", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"category", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"comment", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"replace_if_exists", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
			),
			List.of("name"), null, null, null);
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
		if (currentProgram == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("No program currently loaded")
				.build();
		}

		String name = (String) arguments.get("name");
		String categoryStr = (String) arguments.get("category");
		String comment = (String) arguments.get("comment");
		Boolean replaceIfExists = (Boolean) arguments.get("replace_if_exists");

		if (name == null || name.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'name' is required")
				.build();
		}

		CategoryPath categoryPath = new CategoryPath(categoryStr != null && !categoryStr.isEmpty() ? categoryStr : "/");
		DataTypeManager dtm = currentProgram.getDataTypeManager();

		int tx = currentProgram.startTransaction("Create Structure: " + name);
		boolean commit = false;
		try {
			StructureDataType struct = new StructureDataType(categoryPath, name, 0);
			if (comment != null && !comment.isEmpty()) {
				try {
					struct.setDescription(comment);
				} catch (Exception e) {
					// Best-effort; not all versions support setDescription on StructureDataType
				}
			}

			DataTypeConflictHandler handler = (replaceIfExists != null && replaceIfExists.booleanValue())
				? DataTypeConflictHandler.REPLACE_HANDLER
				: DataTypeConflictHandler.DEFAULT_HANDLER;

			DataType added = dtm.addDataType(struct, handler);
			commit = true;
			return McpSchema.CallToolResult.builder()
				.addTextContent("Created structure '" + added.getName() + "' in category '" + categoryPath.getPath() + "'")
				.build();
		} catch (Exception e) {
			Msg.error(this, "Failed to create structure", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Failed to create structure: " + e.getMessage())
				.build();
		} finally {
			currentProgram.endTransaction(tx, commit);
		}
	}
}
