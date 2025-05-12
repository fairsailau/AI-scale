# Box AI Metadata Extraction API Documentation

## Structured Metadata Extraction

### API Endpoint
```
POST https://api.box.com/2.0/ai/extract_structured
```

### Request Format - CORRECT APPROACH
```json
{
  "items": [
    {
      "id": "file_id",
      "type": "file"
    }
  ],
  "metadata_template": {
    "template_key": "template_key",
    "scope": "enterprise",
    "type": "metadata_template"
  },
  "ai_agent": {
    "type": "ai_agent_extract_structured",
    "basic_text": {
      "model": "google__gemini_2_0_flash_001"
    }
  }
}
```

### Key Parameters

#### Items Array (Required)
- `items`: Array containing file references
  - `id`: Box file ID
  - `type`: Must be "file"

#### Metadata Template (Required for template-based extraction)
- `metadata_template.template_key`: The template key (not `templateKey`)
- `metadata_template.scope`: Usually `"enterprise"` or `"global"`
- `metadata_template.type`: Must be set to `"metadata_template"`

#### AI Agent (Optional)
- `ai_agent.type`: Must be set to `"ai_agent_extract_structured"` for structured extraction
- `ai_agent.basic_text.model`: AI model to use (e.g., "google__gemini_2_0_flash_001")

#### Custom Fields (Alternative to metadata_template)
```json
{
  "items": [
    {
      "id": "file_id",
      "type": "file"
    }
  ],
  "fields": [
    {
      "key": "field_key",
      "displayName": "Field Display Name",
      "type": "string",
      "description": "Field description"
    }
  ],
  "ai_agent": {
    "type": "ai_agent_extract_structured",
    "basic_text": {
      "model": "google__gemini_2_0_flash_001"
    }
  }
}
```

### Important Notes
- If you don't need to override the AI model, you can omit the `ai_agent` field entirely
- When including `ai_agent`, the `type` must be exactly `"ai_agent_extract_structured"` for structured extraction
- Always include the required `type: "metadata_template"` field in template references
- Each field must have a non-empty `displayName`

## Freeform Metadata Extraction

### API Endpoint
```
POST https://api.box.com/2.0/ai/extract
```

### Request Format
```json
{
  "items": [
    {
      "id": "file_id",
      "type": "file"
    }
  ],
  "prompt": "Extract key metadata from this document",
  "ai_agent": {
    "type": "ai_agent_extract",
    "basic_text": {
      "model": "google__gemini_2_0_flash_001"
    }
  }
}
```

### Key Parameters
- `prompt`: The extraction prompt for the AI model
- `ai_agent.type`: Must be set to `"ai_agent_extract"` for freeform extraction

## Common Errors and Solutions

### 400 Bad Request - Invalid AI Agent Type
```json
{
  "type": "error",
  "code": "bad_request",
  "status": 400,
  "message": "Bad request",
  "context_info": {
    "errors": [
      {
        "name": "type",
        "message": "should be equal to one of the allowed values",
        "reason": "invalid_parameter"
      }
    ]
  }
}
```

**Solution**: Use the correct `ai_agent.type` value:
- For structured extraction: `"ai_agent_extract_structured"`
- For freeform extraction: `"ai_agent_extract"`

## Best Practices

1. **Use correct type values** - Each endpoint requires a specific `ai_agent.type` value
2. **Consider omitting ai_agent** - If you don't need to override the default model
3. **Always include required type fields** in metadata templates
4. **Use correct property names** (`template_key` not `templateKey`)
5. **Provide non-empty labels** for all UI elements
6. **Handle API errors gracefully** with appropriate user feedback
7. **Test with both template-based and custom field-based extraction**
