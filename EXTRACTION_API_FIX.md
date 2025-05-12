# Batch Extraction API Fix (400 Bad Request)

## Overview

This document details the fix implemented to resolve the "400 Client Error: Bad Request" errors encountered during batch metadata extraction using the Box AI API.

## Problem

When attempting to perform batch metadata extraction (both freeform and structured), the application was receiving "400 Client Error: Bad Request" responses from the Box API for all files in the batch. This indicated an issue with the format or content of the API request being sent.

## Root Cause Analysis

Upon reviewing the Box API documentation for the `POST /ai/extract` (freeform) and `POST /ai/extract_structured` (structured) endpoints, and comparing it with the implementation in `modules/api_client.py`, the following was identified:

1.  **`ai_agent` Structure:** The Box API requires the `ai_agent` object within the request body to contain *both* `basic_text` and `long_text` fields, even if the same model is used for both. Each of these fields should specify the AI `model` to be used.
2.  **Freeform Implementation (`batch_extract_metadata_freeform`):** The implementation for the freeform batch extraction was only including the `basic_text` field within the `ai_agent` object. It was missing the required `long_text` field.
3.  **Structured Implementation (`batch_extract_metadata_structured`):** The implementation for structured batch extraction correctly included both `basic_text` and `long_text` fields.

The missing `long_text` field in the freeform extraction request payload was causing the Box API to reject the request with a 400 Bad Request error.

## Solution

The fix involved updating the `batch_extract_metadata_freeform` method in `modules/api_client.py` to correctly structure the `ai_agent` object in the request payload.

Specifically, the `long_text` field, containing the specified `ai_model`, was added to the `ai_agent` dictionary alongside the existing `basic_text` field.

## Updated Code (`api_client.py`)

The relevant part of the `batch_extract_metadata_freeform` method was updated as follows:

```python
    def batch_extract_metadata_freeform(self, 
                                       items: List[Dict[str, str]], 
                                       prompt: str, 
                                       ai_model: str = "google__gemini_2_0_flash_001") -> Dict[str, Any]:
        """
        Perform batch freeform metadata extraction using Box AI.
        
        Args:
            items: List of item dictionaries, e.g., [{\'id\': \'file_id_1\', \'type\': \'file\'}, ...]
            prompt: The prompt for the AI model.
            ai_model: The AI model to use (default: google__gemini_2_0_flash_001).
            
        Returns:
            dict: API response containing batch results or error.
        """
        endpoint = "ai/extract"
        data = {
            "items": items,
            "prompt": prompt,
            "ai_agent": {
                "type": "ai_agent_extract",
                "basic_text": {
                    "model": ai_model
                },
                # FIX: Added missing long_text field as required by Box API
                "long_text": {
                    "model": ai_model 
                }
            }
        }
        logger.info(f"Calling batch freeform extraction for {len(items)} items.")
        return self.call_api(endpoint, method="POST", data=data)
```

## Testing

After applying this fix, the batch extraction process (both freeform and structured, assuming a valid configuration) should no longer result in 400 Bad Request errors related to the `ai_agent` structure. The API calls should now proceed, and results (or other potential errors like content processing issues) should be returned correctly.
