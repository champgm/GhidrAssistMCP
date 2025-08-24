/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool to retrieve information about a specific DataType by path or name.
 */
public class GetDataTypeTool implements McpTool {
	@Override
	public String getName() {
		return "get_data_type";
	}

	@Override
	public String getDescription() {
		return "Get details about a DataType (by path or name), optionally including structure components";
	}

	@Override
	public McpSchema.JsonSchema getInputSchema() {
		return new McpSchema.JsonSchema(
			"object",
			Map.of(
				"data_type", new McpSchema.JsonSchema("string", null, null, null, null, null),
				"include_components", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
				"max_components", new McpSchema.JsonSchema("number", null, null, null, null, null)
			),
			List.of("data_type"), null, null, null);
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
		if (currentProgram == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("No program currently loaded")
				.build();
		}

		String dtNameOrPath = (String) arguments.get("data_type");
		Boolean includeComponents = (Boolean) arguments.get("include_components");
		Number maxComponentsNum = (Number) arguments.get("max_components");
		int maxComponents = maxComponentsNum != null ? maxComponentsNum.intValue() : 2000;

		if (dtNameOrPath == null || dtNameOrPath.isEmpty()) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("'data_type' is required (path like '/Cat/Name' or simple name)")
				.build();
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataType dt = resolveDataType(dtm, dtNameOrPath);
		if (dt == null) {
			return McpSchema.CallToolResult.builder()
				.addTextContent("Data type not found: " + dtNameOrPath)
				.build();
		}

		StringBuilder sb = new StringBuilder();
		try {
			describeDataType(dt, includeComponents != null && includeComponents.booleanValue(), maxComponents, sb);
		} catch (Exception e) {
			Msg.error(this, "Error describing data type", e);
			return McpSchema.CallToolResult.builder()
				.addTextContent("Error describing data type: " + e.getMessage())
				.build();
		}

		return McpSchema.CallToolResult.builder()
			.addTextContent(sb.toString())
			.build();
	}

	private DataType resolveDataType(DataTypeManager dtm, String nameOrPath) {
		if (nameOrPath.startsWith("/")) {
			int lastSlash = nameOrPath.lastIndexOf('/');
			String category = lastSlash > 0 ? nameOrPath.substring(0, lastSlash) : "/";
			String nm = lastSlash >= 0 ? nameOrPath.substring(lastSlash + 1) : nameOrPath;
			DataType dt = dtm.getDataType(new CategoryPath(category), nm);
			if (dt != null) return dt;
		}
		return dtm.getDataType(nameOrPath);
	}

	private void describeDataType(DataType dt, boolean includeComponents, int maxComponents, StringBuilder sb) {
		sb.append("Name: ").append(dt.getDisplayName()).append('\n');
		sb.append("Path: ").append(dt.getCategoryPath().getPath()).append('\n');
		sb.append("Kind: ").append(dt.getClass().getSimpleName()).append('\n');
		sb.append("Length: ").append(dt.getLength()).append('\n');

		if (dt instanceof Pointer) {
			Pointer ptr = (Pointer) dt;
			DataType ref = ptr.getDataType();
			sb.append("PointsTo: ").append(ref != null ? ref.getDisplayName() : "<unknown>").append('\n');
		}
		else if (dt instanceof Array) {
			Array arr = (Array) dt;
			DataType elem = arr.getDataType();
			sb.append("ArrayOf: ").append(elem != null ? elem.getDisplayName() : "<unknown>")
				.append(", Count: ").append(arr.getNumElements())
				.append(", ElemLen: ").append(elem != null ? elem.getLength() : -1).append('\n');
		}
		else if (dt instanceof TypedefDataType) {
			TypedefDataType td = (TypedefDataType) dt;
			DataType base = td.getBaseDataType();
			sb.append("TypedefOf: ").append(base != null ? base.getDisplayName() : "<unknown>").append('\n');
		}
		else if (dt instanceof Structure) {
			Structure s = (Structure) dt;
			sb.append("Components: ").append(s.getNumComponents()).append('\n');
			if (includeComponents) {
				DataTypeComponent[] comps = s.getDefinedComponents();
				int shown = 0;
				for (DataTypeComponent c : comps) {
					if (shown >= maxComponents) break;
					sb.append("  [").append(c.getOffset()).append("] ")
						.append(c.getDataType().getDisplayName())
						.append(" len=").append(c.getLength())
						.append(c.getFieldName() != null ? " name=" + c.getFieldName() : "")
						.append('\n');
					shown++;
				}
				if (shown >= maxComponents) {
					sb.append("  ... components truncated at ").append(maxComponents).append('\n');
				}
			}
		}
		else if (dt instanceof Union) {
			Union u = (Union) dt;
			sb.append("Members: ").append(u.getNumComponents()).append('\n');
			if (includeComponents) {
				DataTypeComponent[] comps = u.getComponents();
				int shown = 0;
				for (DataTypeComponent c : comps) {
					if (shown >= maxComponents) break;
					sb.append("  ")
						.append(c.getDataType().getDisplayName())
						.append(" len=").append(c.getLength())
						.append(c.getFieldName() != null ? " name=" + c.getFieldName() : "")
						.append('\n');
					shown++;
				}
				if (shown >= maxComponents) {
					sb.append("  ... members truncated at ").append(maxComponents).append('\n');
				}
			}
		}
		else if (dt instanceof Enum) {
			Enum e = (Enum) dt;
			sb.append("EnumSize: ").append(e.getLength()).append('\n');
			if (includeComponents) {
				String[] names = e.getNames();
				int shown = 0;
				for (String name : names) {
					if (shown >= maxComponents) break;
					long val = e.getValue(name);
					sb.append("  ").append(name).append(" = ").append(val).append('\n');
					shown++;
				}
				if (shown >= maxComponents) {
					sb.append("  ... enum values truncated at ").append(maxComponents).append('\n');
				}
			}
		}
		else if (dt instanceof FunctionDefinition) {
			FunctionDefinition f = (FunctionDefinition) dt;
			sb.append("ReturnType: ").append(f.getReturnType() != null ? f.getReturnType().getDisplayName() : "void").append('\n');
			sb.append("Params: ").append(f.getArguments().length).append('\n');
		}
	}
}
