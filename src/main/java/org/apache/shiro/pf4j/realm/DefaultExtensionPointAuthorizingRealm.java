package org.apache.shiro.pf4j.realm;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.pf4j.authc.token.ExtensionPointAuthenticationToken;
import org.apache.shiro.pf4j.utils.ExtensionPointUtils;

/**
 * Default ExtensionPoint AuthorizingRealm
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class DefaultExtensionPointAuthorizingRealm extends AuthorizingRealmExtensionPoint<ShiroPrincipal> {

	private String extensionParamName = ExtensionPointUtils.EXTENSION_PARAM;
    private String pluginParamName = ExtensionPointUtils.PLUGINID_PARAM;
    
	@Override
	public Class<?> getAuthenticationTokenClass() {
		return ExtensionPointAuthenticationToken.class;// 此Realm只支持ExtensionPointAuthenticationToken
	}
	
	@Override
	protected String getPluginId(ServletRequest request, ServletResponse response) {
        return ExtensionPointUtils.getPluginId(request, response, getPluginParamName());
	}

	@Override
	protected String getExtensionId(ServletRequest request, ServletResponse response) {
        return ExtensionPointUtils.getExtensionId(request, response, getExtensionParamName());
	}

	public String getExtensionParamName() {
		return extensionParamName;
	}

	public void setExtensionParamName(String extensionParamName) {
		this.extensionParamName = extensionParamName;
	}

	public String getPluginParamName() {
		return pluginParamName;
	}

	public void setPluginParamName(String pluginParamName) {
		this.pluginParamName = pluginParamName;
	}

}
