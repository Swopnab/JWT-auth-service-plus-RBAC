// Custom error classes for better error handling (Vanilla JavaScript)

export class AppError extends Error {
    /**
     * @param {number} statusCode - HTTP status code
     * @param {string} message - Error message
     * @param {string} [code] - Error code
     */
    constructor(statusCode, message, code) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.name = 'AppError';
    }
}

export class ValidationError extends AppError {
    /**
     * @param {string} message - Error message
     * @param {Object.<string, string[]>} [errors] - Validation errors
     */
    constructor(message, errors) {
        super(400, message, 'VALIDATION_ERROR');
        this.errors = errors;
        this.name = 'ValidationError';
    }
}

export class UnauthorizedError extends AppError {
    /**
     * @param {string} [message='Unauthorized'] - Error message
     */
    constructor(message = 'Unauthorized') {
        super(401, message, 'UNAUTHORIZED');
        this.name = 'UnauthorizedError';
    }
}

export class ForbiddenError extends AppError {
    /**
     * @param {string} [message='Forbidden'] - Error message
     */
    constructor(message = 'Forbidden') {
        super(403, message, 'FORBIDDEN');
        this.name = 'ForbiddenError';
    }
}

export class NotFoundError extends AppError {
    /**
     * @param {string} [message='Resource not found'] - Error message
     */
    constructor(message = 'Resource not found') {
        super(404, message, 'NOT_FOUND');
        this.name = 'NotFoundError';
    }
}

export class ConflictError extends AppError {
    /**
     * @param {string} message - Error message
     */
    constructor(message) {
        super(409, message, 'CONFLICT');
        this.name = 'ConflictError';
    }
}

export class RateLimitError extends AppError {
    /**
     * @param {string} [message='Too many requests'] - Error message
     */
    constructor(message = 'Too many requests') {
        super(429, message, 'RATE_LIMIT_EXCEEDED');
        this.name = 'RateLimitError';
    }
}

/**
 * Format error response for API
 * @param {Error|AppError} error - Error object
 * @returns {Object} Formatted error response
 */
export function formatErrorResponse(error) {
    if (error instanceof AppError) {
        return {
            error: {
                message: error.message,
                code: error.code,
                ...(error instanceof ValidationError && error.errors ? { errors: error.errors } : {}),
            },
        };
    }

    // Don't leak internal errors in production
    return {
        error: {
            message: 'An unexpected error occurred',
            code: 'INTERNAL_ERROR',
        },
    };
}
