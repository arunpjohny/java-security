package com.arun.security.exception;

public class PrivateKeyNotFoundException extends Exception {
	private static final long serialVersionUID = 1L;

	public PrivateKeyNotFoundException() {
		super();
	}

	public PrivateKeyNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	public PrivateKeyNotFoundException(String message) {
		super(message);
	}

	public PrivateKeyNotFoundException(Throwable cause) {
		super(cause);
	}

}
