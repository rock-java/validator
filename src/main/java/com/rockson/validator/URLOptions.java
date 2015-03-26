package com.rockson.validator;

import java.util.HashSet;
import java.util.Set;

public class URLOptions {
	private Set<String> protocols;
	private boolean requireTld = true;
	private boolean requireProtocol = false;
	private boolean allowUnderscores = false;
	private Set<String> hostWhitelist;
	private Set<String> hostBlacklist;
	private boolean allowTrailingDot = false;
	private boolean allowProtocolRelativeUrls = false;
	private boolean allowEmptyHost = false;

	public URLOptions() {
		protocols = new HashSet<String>();
		protocols.add("http");
		protocols.add("https");
		protocols.add("ftp");
	}

	public URLOptions(Set<String> protocols, boolean requireTld, boolean requireProtocol, boolean allowUnderscores,
			Set<String> hostWhitelist, Set<String> hostBlacklist, boolean allowTrailingDot,
			boolean allowProtocolRelativeUrls , boolean allowEmptyHost) {
		super();
		this.protocols = protocols;
		this.requireTld = requireTld;
		this.requireProtocol = requireProtocol;
		this.allowUnderscores = allowUnderscores;
		this.hostWhitelist = hostWhitelist;
		this.hostBlacklist = hostBlacklist;
		this.allowTrailingDot = allowTrailingDot;
		this.allowProtocolRelativeUrls = allowProtocolRelativeUrls;
		this.allowEmptyHost = allowEmptyHost;
	}

	public boolean isAllowEmptyHost() {
		return allowEmptyHost;
	}

	public void setAllowEmptyHost(boolean allowEmptyHost) {
		this.allowEmptyHost = allowEmptyHost;
	}

	public Set<String> getHostWhitelist() {
		return hostWhitelist;
	}

	public void setHostWhitelist(Set<String> hostWhitelist) {
		this.hostWhitelist = hostWhitelist;
	}

	public Set<String> getHostBlacklist() {
		return hostBlacklist;
	}

	public void setHostBlacklist(Set<String> hostBlacklist) {
		this.hostBlacklist = hostBlacklist;
	}

	public Set<String> getProtocols() {
		return protocols;
	}

	public void setProtocols(Set<String> protocols) {
		this.protocols = protocols;
	}

	public boolean isRequireTld() {
		return requireTld;
	}

	public void setRequireTld(boolean requireTld) {
		this.requireTld = requireTld;
	}

	public boolean isRequireProtocol() {
		return requireProtocol;
	}

	public void setRequireProtocol(boolean requireProtocol) {
		this.requireProtocol = requireProtocol;
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

	public boolean isAllowProtocolRelativeUrls() {
		return allowProtocolRelativeUrls;
	}

	public void setAllowProtocolRelativeUrls(boolean allowProtocolRelativeUrls) {
		this.allowProtocolRelativeUrls = allowProtocolRelativeUrls;
	}

}
