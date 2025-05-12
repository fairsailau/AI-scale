# Structured Metadata Extraction API Fix

## Problem Overview

The Box Metadata AI application was encountering "400 Client Error: Bad Request" errors when attempting to perform batch structured metadata extraction using the Box AI API. All files in the batch were failing with this error, indicating an issue with the format of the API request being sent.

## Root Cause Analysis

After examining the error logs, API request structure, and Box API documentation, we identified that the structured extraction API request was missing a required parameter:

1. The Box AI API endpoint `/ai/extract_structured` requires a `fields` parameter in the request payload when using a metadata template.
2. Our implementation in `batch_extract_metadata_structured` method was only including:
   - `items` (list of files)
   - `metadata_template` (template information)
   - `ai_agent` (AI model configuration)
3. The missing `fields` parameter is essential as it tells the Box AI which fields to extract from the documents.

## Solution Implemented

We implemented a comprehensive fix with the following changes:

### 1. Updated the API Client Method Signature

Modified the `batch_extract_metadata_structured` method in `api_client.py` to include the required `fields` parameter:

```python
def batch_extract_metadata_structured(self, 
                                     items: List[Dict[str, str]], 
                                     template_scope: str, 
                                     template_key: str, 
                                     fields: List[Dict[str, Any]],  # Added fields parameter
                                     ai_model: str = "google__gemini_2_0_flash_001") -> Dict[str, Any]:
```

### 2. Updated the Request Payload Structure

Modified the request payload to include the `fields` parameter:

```python
data = {
    "items": items,
    "metadata_template": {
        "template_key": template_key,
        "scope": template_scope,
        "type": "metadata_template"
    },
    "fields": fields,  # Added fields to the request payload
    "ai_agent": {
        "type": "ai_agent_extract", 
        "basic_text": {
            "model": ai_model
        },
        "long_text": {
            "model": ai_model
        }
    }
}
```

### 3. Updated the Processing Module

Modified the `_process_batch_extraction` function in `processing.py` to:

1. Fetch the template schema to get the fields
2. Extract the fields from the schema
3. Pass the fields to the API client method

```python
# Fetch schema to get fields
schema_response = api_client.get_metadata_template_schema(
    scope=template_scope_for_api, 
    template_key=template_key,
    use_cache=use_template_cache
)

if "error" in schema_response:
     # Handle error...

# Extract fields from schema for the API call
template_fields = schema_response.get("fields", [])
if not template_fields:
     # Handle error...

# Pass the fields to the API client method
api_response = api_client.batch_extract_metadata_structured(
    items=items,
    template_scope=template_scope_for_api,
    template_key=template_key,
    fields=template_fields,  # Pass the extracted fields
    ai_model=ai_model
)
```

### 4. Added Better Error Handling

Enhanced error handling to provide more detailed error messages when:
- Template schema cannot be retrieved
- Template has no fields defined
- API request fails

## Expected Results

With these changes, the structured metadata extraction should now:
1. Correctly include the required `fields` parameter in the API request
2. Successfully process files without 400 Bad Request errors
3. Provide more detailed error messages if issues occur

## Testing

The fix should be tested by:
1. Selecting files for processing
2. Configuring structured metadata extraction with a template
3. Starting the processing
4. Verifying that the extraction completes without 400 Bad Request errors

## Additional Notes

This fix maintains all existing functionality while addressing the specific API request format issue. The automatic metadata application feature continues to work as designed, triggered only when the checkbox is selected.
