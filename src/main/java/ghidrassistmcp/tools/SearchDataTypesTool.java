/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that searches data types in the DataTypeManager by name or path.
 */
public class SearchDataTypesTool implements McpTool {
	@Override
	public String getName() {
		return "search_data_types";
	}

	@Override
	public String getDescription() {
		return "Search data types by name or path (substring or regex)";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"query", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"root_category", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"regex", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
				"case_insensitive", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
				"max_items", new McpSchema.JsonSchema("number", null, null, null, null, null)
			),
			List.of("query"), null, null, null);
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
		if (currentProgram == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("No program currently loaded")
				.build();
		}

		String query = (String) arguments.get("query");
		String rootCategory = (String) arguments.get("root_category");
		Boolean regex = (Boolean) arguments.get("regex");
		Boolean caseInsensitive = (Boolean) arguments.get("case_insensitive");
		Number maxItemsNum = (Number) arguments.get("max_items");

		if (query == null || query.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'query' is required")
				.build();
		}

		int maxItems = maxItemsNum != null ? maxItemsNum.intValue() : 2000;
		Pattern pattern = null;
		String needle = query;
		if (regex != null && regex.booleanValue()) {
			int flags = (caseInsensitive != null && caseInsensitive.booleanValue()) ? Pattern.CASE_INSENSITIVE : 0;
			try {
				pattern = Pattern.compile(query, flags);
			} catch (Exception e) {
				return McpSchema.CallToolResult.builder()
					.addTextContent("Invalid regex: " + e.getMessage())
					.build();
			}
		} else if (caseInsensitive != null && caseInsensitive.booleanValue()) {
			needle = query.toLowerCase();
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		Category start;
		if (rootCategory != null && !rootCategory.isEmpty()) {
			CategoryPath cp = new CategoryPath(rootCategory);
			start = dtm.getCategory(cp);
			if (start == null) {
				return McpSchema.CallToolResult.builder()
					.addTextContent("Category not found: " + rootCategory)
					.build();
			}
		} else {
			start = dtm.getRootCategory();
		}

		StringBuilder sb = new StringBuilder();
		int[] count = new int[] { 0 };
		try {
			searchCategory(start, pattern, needle, caseInsensitive != null && caseInsensitive.booleanValue(), maxItems, count, sb);
		} catch (Exception e) {
			Msg.error(this, "Error searching data types", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Error searching data types: " + e.getMessage())
				.build();
		}

		if (count[0] == 0) {
			sb.append("No matches");
		}
		else if (count[0] >= maxItems) {
			sb.append("\n... truncated at ").append(maxItems).append(" items");
		}

		return McpSchema.CallToolResult.builder()
			.addTextContent(sb.toString())
			.build();
	}

	private void searchCategory(Category category, Pattern pattern, String needle, boolean ci, int maxItems, int[] count, StringBuilder sb) {
		if (category == null || count[0] >= maxItems) return;

		DataType[] dts = category.getDataTypes();
		if (dts != null) {
			for (DataType dt : dts) {
				if (count[0] >= maxItems) break;
				String name = dt.getDisplayName();
				String path = category.getCategoryPath().getPath();
				String full = (path.endsWith("/") ? path : path + "/") + name;
				boolean match;
				if (pattern != null) {
					match = pattern.matcher(full).find() || pattern.matcher(name).find();
				} else if (ci) {
					match = name.toLowerCase().contains(needle) || full.toLowerCase().contains(needle);
				} else {
					match = name.contains(needle) || full.contains(needle);
				}
				if (match) {
					sb.append(full).append('\n');
					count[0]++;
				}
			}
		}

		Category[] subs = category.getCategories();
		if (subs != null) {
			for (Category sub : subs) {
				if (count[0] >= maxItems) break;
				searchCategory(sub, pattern, needle, ci, maxItems, count, sb);
			}
		}
	}
}
