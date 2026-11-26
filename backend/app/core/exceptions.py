from fastapi import HTTPException, status


class WebGuardException(HTTPException):
    def __init__(self, status_code: int, detail: str, code: str = "error") -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.code = code


class UnauthorizedTargetError(WebGuardException):
    def __init__(self, detail: str = "Target domain is not verified or authorized for scanning.") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail, code="target_not_authorized")


class SSRFProtectionError(WebGuardException):
    def __init__(self, detail: str = "Target resolves to a forbidden or private network address.") -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail, code="ssrf_blocked")


class ResourceNotFoundError(WebGuardException):
    def __init__(self, resource: str = "Resource") -> None:
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource} not found.", code="not_found")


class ValidationFailureError(WebGuardException):
    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail, code="validation_error")
