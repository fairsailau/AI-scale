# Box Metadata AI V4.1 - Fixed Version

## Overview
This is a fixed version of the Box Metadata AI V4.1 application that addresses critical issues with structured metadata extraction. The application now correctly formats API requests according to Box API specifications.

## Fixed Issues

### 1. Structured Metadata Extraction
- **Root Cause Identified**: The application was using incorrect API request format for structured metadata extraction
- **Issues Fixed**:
  - Changed `ai_agent.type` from `"ai_agent_extract"` to `"ai_agent_extract_structured"`
  - Changed metadata template key from camelCase `"templateKey"` to snake_case `"template_key"`
  - Used full template ID for scope instead of just the first part
  - Added required `"type": "metadata_template"` field to metadata template

### 2. API Request Format
The application now uses the correct format for structured metadata extraction:

```json
{
  "items": [{"id": "file_id", "type": "file"}],
  "metadata_template": {
    "template_key": "template_key",
    "scope": "enterprise_12345",
    "type": "metadata_template"
  },
  "ai_agent": {
    "type": "ai_agent_extract_structured",
    "basic_text": {
      "model": "azure__openai__gpt_4o_mini"
    }
  }
}
```

## Installation
1. Extract the zip file
2. Run the application using Streamlit:
```
streamlit run app.py
```

## Testing
A test script is included to verify the fixes:
```
python test_structured_extraction.py
```

## Requirements
- Python 3.7+
- Streamlit
- Box SDK
- Internet connection for Box API access
