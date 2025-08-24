/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

/**
 * MCP tool that lists data types in the DataTypeManager, traversing the category tree.
 */
public class ListDataTypesTool implements McpTool {
	@Override
	public String getName() {
		return "list_data_types";
	}

	@Override
	public String getDescription() {
		return "List data types organized by category tree (optional root and depth)";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"root_category", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"max_depth", new McpSchema.JsonSchema("number", null, null, null, null, null),
				"name_contains", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"max_items", new McpSchema.JsonSchema("number", null, null, null, null, null)
			),
			null, null, null, null);
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
		if (currentProgram == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("No program currently loaded")
				.build();
		}

		String rootCategory = (String) arguments.get("root_category");
		Number maxDepthNum = (Number) arguments.get("max_depth");
		String nameContains = (String) arguments.get("name_contains");
		Number maxItemsNum = (Number) arguments.get("max_items");

		int maxDepth = maxDepthNum != null ? maxDepthNum.intValue() : Integer.MAX_VALUE;
		int maxItems = maxItemsNum != null ? maxItemsNum.intValue() : 2000;
		final String nameFilter = nameContains != null && !nameContains.isEmpty() ? nameContains.toLowerCase() : null;

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

		int[] count = new int[] { 0 };
		boolean[] truncated = new boolean[] { false };
		Node rootNode;
		try {
			rootNode = buildTree(start, 0, maxDepth, nameFilter, maxItems, count, truncated);
		} catch (Exception e) {
			Msg.error(this, "Error listing data types", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Error listing data types: " + e.getMessage())
				.build();
		}

		Map<String, Object> out = new HashMap<>();
		out.put("root", rootNode != null ? rootNode : new Node("/", "/", "category"));
		out.put("truncated", truncated[0]);
		out.put("max_items", maxItems);

		try {
			ObjectWriter ow = new ObjectMapper().writer();
			String json = ow.writeValueAsString(out);
			return McpSchema.CallToolResult.builder()
				.addTextContent(json)
				.build();
		} catch (Exception e) {
			Msg.error(this, "Failed to serialize data types tree", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Failed to serialize data types tree: " + e.getMessage())
				.build();
		}
	}

	private Node buildTree(Category category, int depth, int maxDepth, String nameFilter, int maxItems, int[] count, boolean[] truncated) {
		if (category == null || depth > maxDepth) {
			return null;
		}

		String catPath = category.getCategoryPath().getPath();
		String catName = "/".equals(catPath) ? "/" : catPath.substring(catPath.lastIndexOf('/') + 1);
		Node node = new Node(catName, catPath, "category");

		// Add data type children in this category
		DataType[] dts = category.getDataTypes();
		if (dts != null) {
			for (DataType dt : dts) {
				if (count[0] >= maxItems) {
					truncated[0] = true;
					break;
				}
				String dn = dt.getDisplayName();
				if (nameFilter == null || dn.toLowerCase().contains(nameFilter)) {
					String fullPath = (catPath.endsWith("/") ? catPath : catPath + "/") + dn;
					node.children.add(new Node(dn, fullPath, "data_type"));
					count[0]++;
				}
			}
		}

		// Recurse into subcategories and only keep those that produce content
		Category[] subs = category.getCategories();
		if (subs != null) {
			for (Category sub : subs) {
				if (count[0] >= maxItems) {
					truncated[0] = true;
					break;
				}
				Node child = buildTree(sub, depth + 1, maxDepth, nameFilter, maxItems, count, truncated);
				if (child != null && !child.children.isEmpty()) {
					node.children.add(child);
				}
			}
		}

		// If this category has no children and isn't the root, return null to prune empty leaves
		if (node.children.isEmpty() && depth > 0) {
			return null;
		}
		return node;
	}

	private static class Node {
		public String name;
		public String path;
		public String kind;
		public List<Node> children = new ArrayList<>();

		Node(String name, String path, String kind) {
			this.name = name;
			this.path = path;
			this.kind = kind;
		}
	}
}
