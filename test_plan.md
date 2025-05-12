# Box AI Metadata Extraction API Test Plan

## Test Case 1: Structured Metadata with Template

```json
{
  "items": [{"id": "file_id", "type": "file"}],
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

## Test Case 2: Structured Metadata without AI Agent Override

```json
{
  "items": [{"id": "file_id", "type": "file"}],
  "metadata_template": {
    "template_key": "template_key",
    "scope": "enterprise",
    "type": "metadata_template"
  }
}
```

## Test Case 3: Freeform Metadata Extraction

```json
{
  "items": [{"id": "file_id", "type": "file"}],
  "prompt": "Extract key metadata from this document",
  "ai_agent": {
    "type": "ai_agent_extract",
    "basic_text": {
      "model": "google__gemini_2_0_flash_001"
    }
  }
}
```

## Expected Results

1. All API calls should return 200 OK status
2. No 400 Bad Request errors related to ai_agent.type
3. Structured metadata extraction should work with both template and custom fields
4. Freeform metadata extraction should continue to work as before
