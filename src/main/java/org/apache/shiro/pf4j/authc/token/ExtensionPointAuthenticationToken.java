/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.pf4j.authc.token;

import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.biz.authc.token.LoginType;

/**
 * Pf4j ExtensionPoint Authentication Token
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class ExtensionPointAuthenticationToken extends DefaultAuthenticationToken {

	public ExtensionPointAuthenticationToken() {
		super();
	}

	public ExtensionPointAuthenticationToken(String username, String password) {
		super(username, password);
	}

	public ExtensionPointAuthenticationToken(String username, String password, LoginType loginType) {
		super(username, password, loginType);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password) {
		super(username, password);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, LoginType loginType) {
		super(username, password, loginType);
	}

	public ExtensionPointAuthenticationToken(String username, String password, String captcha) {
		super(username, password, captcha);
	}

	public ExtensionPointAuthenticationToken(String username, String password, String captcha, LoginType loginType) {
		super(username, password, captcha, loginType);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String captcha) {
		super(username, password, captcha);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String captcha, LoginType loginType) {
		super(username, password, captcha, loginType);
	}

	public ExtensionPointAuthenticationToken(String username, String password, String userType, String captcha) {
		this(username, password != null ? password.toCharArray() : null, userType, captcha);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String userType, String captcha) {
		super(username, password, userType, captcha);
	}

	public ExtensionPointAuthenticationToken(String username, String password, String userType, boolean rememberMe) {
		super(username, password, userType, rememberMe);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String userType, boolean rememberMe) {
		super(username, password, userType, rememberMe);
	}

	public ExtensionPointAuthenticationToken(String username, String password, String userType, String host,
			boolean rememberMe) {
		super(username, password, userType, host, rememberMe);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String userType, String host,
			boolean rememberMe) {
		super(username, password, userType, host, rememberMe);
	}

	public ExtensionPointAuthenticationToken(String username, String password, String userType, String captcha, String host,
			boolean rememberMe) {
		super(username, password, userType, captcha, host, rememberMe);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String userType, String captcha, String host,
			boolean rememberMe) {
		super(username, password, userType, captcha, host, rememberMe);
	}

	public ExtensionPointAuthenticationToken(String username, char[] password, String userType, String captcha, String host,
			boolean rememberMe, LoginType loginType) {
		super(username, password, userType, captcha, host, rememberMe, loginType);
	}
	
}
