/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that creates a category (folder) in the DataTypeManager.
 */
public class CreateDataTypeCategoryTool implements McpTool {
	@Override
	public String getName() {
		return "create_data_type_category";
	}

	@Override
	public String getDescription() {
		return "Create a data type category (folder) under the specified path";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"path", new McpSchema.JsonSchema("string", null, null, null, null, null)
			),
			List.of("path"), null, null, null);
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
		if (currentProgram == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("No program currently loaded")
				.build();
		}

		String path = (String) arguments.get("path");
		if (path == null || path.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'path' is required, e.g. '/MyCategory/Sub' or '/NewFolder'")
				.build();
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		int tx = currentProgram.startTransaction("Create DataType Category");
		boolean commit = false;
		try {
			CategoryPath cp = new CategoryPath(path);
			Category cat = dtm.createCategory(cp);
			commit = true;
			return McpSchema.CallToolResult.builder()
				.addTextContent("Created category: " + cat.getCategoryPath().getPath())
				.build();
		} catch (Exception e) {
			Msg.error(this, "Failed to create category", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Failed to create category: " + e.getMessage())
				.build();
		} finally {
			currentProgram.endTransaction(tx, commit);
		}
	}
}
