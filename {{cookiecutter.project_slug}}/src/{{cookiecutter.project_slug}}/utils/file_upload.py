#!/usr/bin/env python3
"""File upload utilities for multipart/form-data requests"""

from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional, Union

import requests
from requests_toolbelt import MultipartEncoder


class FileUploader:
    """Wrapper for handling file uploads with multipart/form-data"""

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def upload(
        self,
        url: str,
        file_content: Union[str, bytes],
        filename: str,
        file_field_name: str = "file",
        content_type: Optional[str] = None,
        additional_fields: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """Upload a file using multipart/form-data

        Args:
            url: Target URL for the upload
            file_content: File content (string or bytes)
            filename: Name of the file (can include encoded characters like %00)
            file_field_name: Form field name for the file (default: "file")
            content_type: MIME type of the file (default: auto-detect)
            additional_fields: Additional form fields to include
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response object from the upload request
        """
        if isinstance(file_content, str):
            file_content = file_content.encode()

        fields = {}

        # Add file field
        fields[file_field_name] = (filename, BytesIO(file_content), content_type or self._guess_content_type(filename))

        # Add additional fields if provided
        if additional_fields:
            fields.update(additional_fields)

        # Create multipart encoder
        encoder = MultipartEncoder(fields=fields)

        # Prepare headers
        headers = kwargs.pop("headers", {})
        headers["Content-Type"] = encoder.content_type

        return self.session.post(url, data=encoder, headers=headers, **kwargs)

    def upload_with_bypass(
        self,
        url: str,
        file_content: Union[str, bytes],
        filename: str,
        bypass_technique: Optional[str] = None,
        file_field_name: str = "file",
        additional_fields: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """Upload a file with various bypass techniques

        Args:
            url: Target URL for the upload
            file_content: File content
            filename: Base filename
            bypass_technique: Technique to use ('null_byte', 'double_extension', 'case_variation', 'mime_mismatch')
            file_field_name: Form field name for the file
            additional_fields: Additional form fields
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response object from the upload request
        """
        # Get base name and extension
        if "." in filename:
            base, ext = filename.rsplit(".", 1)
        else:
            base, ext = filename, ""

        # Apply bypass technique to filename
        modified_filename = filename
        content_type = None

        if bypass_technique == "null_byte":
            # Add null byte with safe extension
            modified_filename = f"{base}.{ext}%00.jpg"
            content_type = "image/jpeg"
        elif bypass_technique == "double_extension":
            # Use double extension with safe outer extension
            modified_filename = f"{base}.jpg.{ext}"
            content_type = "image/jpeg"
        elif bypass_technique == "case_variation":
            # Use case variation on extension
            modified_filename = f"{base}.{ext.upper()}"
        elif bypass_technique == "mime_mismatch":
            # Keep filename but use different MIME type
            content_type = "image/jpeg"

        return self.upload(
            url=url,
            file_content=file_content,
            filename=modified_filename,
            file_field_name=file_field_name,
            content_type=content_type,
            additional_fields=additional_fields,
            **kwargs,
        )

    def upload_from_path(
        self,
        url: str,
        file_path: Union[str, Path],
        custom_filename: Optional[str] = None,
        file_field_name: str = "file",
        content_type: Optional[str] = None,
        additional_fields: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """Upload a file from disk

        Args:
            url: Target URL for the upload
            file_path: Path to the file on disk
            custom_filename: Custom filename to use (default: actual filename)
            file_field_name: Form field name for the file
            content_type: MIME type of the file (default: auto-detect)
            additional_fields: Additional form fields
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response object from the upload request
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            content = f.read()

        filename = custom_filename or file_path.name

        return self.upload(
            url=url,
            file_content=content,
            filename=filename,
            file_field_name=file_field_name,
            content_type=content_type,
            additional_fields=additional_fields,
            **kwargs,
        )

    @staticmethod
    def _guess_content_type(filename: str) -> str:
        """Guess content type from filename"""
        # Clean filename of encoded characters for extension detection
        clean_name = filename.lower().replace("%00", "")

        # Get the last extension (in case of double extensions)
        if "." in clean_name:
            ext = clean_name.split(".")[-1]
        else:
            return "application/octet-stream"

        mime_types = {
            # Web scripts
            "php": "application/x-php",
            "asp": "application/x-asp",
            "aspx": "application/x-aspx",
            "jsp": "application/x-jsp",
            "py": "text/x-python",
            "rb": "text/x-ruby",
            "pl": "text/x-perl",
            # Images
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "bmp": "image/bmp",
            "svg": "image/svg+xml",
            # Documents
            "txt": "text/plain",
            "html": "text/html",
            "htm": "text/html",
            "xml": "text/xml",
            "pdf": "application/pdf",
            "doc": "application/msword",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            # Archives
            "zip": "application/zip",
            "tar": "application/x-tar",
            "gz": "application/gzip",
            "rar": "application/x-rar-compressed",
            # Others
            "json": "application/json",
            "js": "application/javascript",
            "css": "text/css",
        }

        return mime_types.get(ext, "application/octet-stream")


def quick_upload(
    session: requests.Session,
    url: str,
    content: Union[str, bytes],
    filename: str,
    submit_button: Optional[tuple[str, str]] = None,
) -> requests.Response:
    """Quick helper function for simple file uploads

    Args:
        session: Requests session to use
        url: Target URL
        content: Content to upload
        filename: Filename to use
        submit_button: Optional tuple of (field_name, field_value) for submit button

    Returns:
        Response object
    """
    uploader = FileUploader(session)

    additional_fields = {}
    if submit_button:
        additional_fields[submit_button[0]] = submit_button[1]

    return uploader.upload(
        url=url,
        file_content=content,
        filename=filename,
        additional_fields=additional_fields,
    )