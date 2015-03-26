package com.rockson.validator;

/**
 * EmailOptions defaults to { allowDisplayName: false, allowUtf8LocalPart: true }. If allowDisplayName is set to true,
 * the validator will also match Display Name <email-address>. If allowUtf8LocalPart is set to false, the validator will
 * not allow any non-English UTF8 character in email address' local part.
 * 
 *
 */
public class EmailOptions {
	/**
	 * If allowDisplayName is set to true, the validator will also match Display Name <email-address>
	 */
	private boolean allowDisplayName = false;
	/**
	 * If allowUtf8LocalPart is set to false, the validator will not allow any non-English UTF8 character in email
	 * address' local part.
	 */
	private boolean allowUtf8LocalPart = true;

	public EmailOptions() {
	}

	public EmailOptions(boolean allowDisplayName, boolean allowUtf8LocalPart) {
		this.allowDisplayName = allowDisplayName;
		this.allowUtf8LocalPart = allowUtf8LocalPart;
	}

	public boolean isAllowDisplayName() {
		return allowDisplayName;
	}

	public void setAllowDisplayName(boolean allowDisplayName) {
		this.allowDisplayName = allowDisplayName;
	}

	public boolean isAllowUtf8LocalPart() {
		return allowUtf8LocalPart;
	}

	public void setAllowUtf8LocalPart(boolean allowUtf8LocalPart) {
		this.allowUtf8LocalPart = allowUtf8LocalPart;
	}

}
