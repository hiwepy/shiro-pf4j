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
package org.apache.shiro.pf4j.authc.point;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.pf4j.ExtensionPoint;

public interface AuthenticatingExtensionPoint extends ExtensionPoint {

	/**
     * <p>Returns {@code true} if this filter should filter the specified request, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@code FilterChain}.
     * </p>
     * <p>This default implementation merely returns the value of isEnabled(), which is
     * {@code true} by default (to ensure the filter always executes by default), but it can be overridden by
     * subclasses for request-specific behavior if necessary.  For example, a filter could be enabled or disabled
     * based on the request path being accessed.
     * </p>
     * <b>Helpful Hint:</b> if your subclass extends {@link org.apache.shiro.web.filter.PathMatchingFilter PathMatchingFilter},
     * you may wish to instead override the
     * {@link org.apache.shiro.web.filter.PathMatchingFilter#isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String, Object)
     * PathMatchingFilter.isEnabled(request,response,path,pathSpecificConfig)}
     * method if you want to make your enable/disable decision based on any path-specific configuration.
     *
     * @param request the incoming servlet request
     * @param response the outbound servlet response
     * @return {@code true} if this filter should filter the specified request, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@code FilterChain}.
     * @throws IOException in the case of any IO error
     * @throws ServletException in the case of any error
     */
    boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException;
	
    boolean isPointSubmission(ServletRequest request, ServletResponse response);
    
	/**
     * Returns <code>true</code> if the request is allowed to proceed through the filter normally, or <code>false</code>
     * if the request should be handled by the
     * {@link #onAccessDenied(ServletRequest,ServletResponse,Object) onAccessDenied(request,response,mappedValue)}
     * method instead.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings.
     * @return <code>true</code> if the request should proceed through the filter normally, <code>false</code> if the
     *         request should be processed by this filter's
     *         {@link #onAccessDenied(ServletRequest,ServletResponse,Object)} method instead.
     */
    boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) ;

    /**
     * <p>Returns <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     * </p>
     * The default implementation merely returns <code>true</code> if the incoming request matches the configured
     * loginUrl by calling <code>pathsMatch(loginUrl, request)</code>.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     */
    boolean isLoginRequest(ServletRequest request, ServletResponse response);

    /**
     * This default implementation merely returns <code>true</code> if the request is an HTTP <code>POST</code>,
     * <code>false</code> otherwise. Can be overridden by subclasses for custom login submission detection behavior.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse.
     * @return <code>true</code> if the request is an HTTP <code>POST</code>, <code>false</code> otherwise.
     */
	boolean isLoginSubmission(ServletRequest request, ServletResponse response);
    
    /**
     * <p>Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method, retaining the {@code mappedValue} that was used during configuration.
     * </p>
     * This method immediately delegates to onAccessDenied(ServletRequest,ServletResponse) as a
     * convenience in that most post-denial behavior does not need the mapped config again.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the config specified for the filter in the matching request's filter chain.
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     */
    boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception;
   
	AuthenticationToken createToken(ServletRequest request, ServletResponse response);

	boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response)
			throws Exception;

	boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response);

	boolean onAccessSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response);

	boolean onAccessFailure(AuthenticationToken token, Exception e, ServletRequest request,
			ServletResponse response);
    
	 /**
     * <p>Executes cleanup logic in the {@code finally} code block in the doFilterInternal implementation.
     * </p>
     * as well as handles any exceptions properly.
     *
     * @param request  the incoming {@code ServletRequest}
     * @param response the outgoing {@code ServletResponse}
     * @param existing any exception that might have occurred while executing the {@code FilterChain} or
     *                 pre or post advice, or {@code null} if the pre/chain/post execution did not throw an {@code Exception}.
     * @throws ServletException if any exception other than an {@code IOException} is thrown.
     * @throws IOException      if the pre/chain/post execution throw an {@code IOException}
     */
    void cleanup(ServletRequest request, ServletResponse response, Exception existing)
            throws ServletException, IOException;
    
    boolean logout(ServletRequest request, ServletResponse response, Subject subject);
            
}
