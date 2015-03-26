package com.rockson.validator;

/**
 * FQDNOptions defaults to { require_tld: true, allow_underscores: false, allow_trailing_dot: false }.
 *
 */
public class FQDNOptions {
	private boolean requireTld = true;
	private boolean allowUnderscores = false;
	private boolean allowTrailingDot = false;
	public FQDNOptions() {
	}

	public FQDNOptions(boolean requireTld, boolean allowUnderscores, boolean allowTrailingDot) {
		this.requireTld = requireTld;
		this.allowUnderscores = allowUnderscores;
		this.allowTrailingDot = allowTrailingDot;
	}

	public boolean isRequireTld() {
		return requireTld;
	}

	public void setRequireTld(boolean requireTld) {
		this.requireTld = requireTld;
	}

	public boolean isAllowUnderscores() {
		return allowUnderscores;
	}

	public void setAllowUnderscores(boolean allowUnderscores) {
		this.allowUnderscores = allowUnderscores;
	}

	public boolean isAllowTrailingDot() {
		return allowTrailingDot;
	}

	public void setAllowTrailingDot(boolean allowTrailingDot) {
		this.allowTrailingDot = allowTrailingDot;
	}

}
