/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.data.publisher.application.authentication.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal
        .AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.AuthenticationData;

import java.util.UUID;

public class TenantDASLoginDataPublisher extends DASLoginDataPublisherImpl {

    @Override
    protected void publishAuthenticationData(AuthenticationData authenticationData) {

        try {
            String roleList = null;
            if (FrameworkConstants.LOCAL_IDP_NAME.equalsIgnoreCase(authenticationData.getIdentityProviderType())) {
                roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain() + "/" + authenticationData
                        .getUsername(), authenticationData.getTenantDomain());
            } else if (StringUtils.isNotEmpty(authenticationData.getLocalUsername())) {
                roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain() + "/" + authenticationData
                        .getLocalUsername(), authenticationData.getTenantDomain());
            }

            Object[] payloadData = new Object[23];
            payloadData[0] = authenticationData.getContextId();
            payloadData[1] = authenticationData.getEventId();
            payloadData[2] = authenticationData.getEventType();
            payloadData[3] = authenticationData.isAuthnSuccess();
            payloadData[4] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.USERNAME, authenticationData.getUsername());
            payloadData[5] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.USERNAME, authenticationData.getLocalUsername());
            payloadData[6] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.USER_STORE_DOMAIN, authenticationData.getUserStoreDomain());
            payloadData[7] = authenticationData.getTenantDomain();
            payloadData[8] = authenticationData.getRemoteIp();
            payloadData[9] = AuthPublisherConstants.NOT_AVAILABLE;
            payloadData[10] = authenticationData.getInboundProtocol();
            payloadData[11] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.SERVICE_PROVIDER, authenticationData
                    .getServiceProvider());
            payloadData[12] = authenticationData.isRememberMe();
            payloadData[13] = authenticationData.isForcedAuthn();
            payloadData[14] = authenticationData.isPassive();
            payloadData[15] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.ROLES, roleList);
            payloadData[16] = String.valueOf(authenticationData.getStepNo());
            payloadData[17] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.IDENTITY_PROVIDER, authenticationData.getIdentityProvider());
            payloadData[18] = authenticationData.isSuccess();
            payloadData[19] = authenticationData.getAuthenticator();
            payloadData[20] = authenticationData.isInitialLogin();
            payloadData[21] = authenticationData.getIdentityProviderType();
            payloadData[22] = System.currentTimeMillis();

            String[] publishingDomains = (String[]) authenticationData.getParameter(AuthPublisherConstants.TENANT_ID);
            if (publishingDomains != null && publishingDomains.length > 0) {

                try {
                    FrameworkUtils.startTenantFlow(authenticationData.getTenantDomain());
                    for (String publishingDomain : publishingDomains) {
                        Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);

                        Event event = new Event(AuthPublisherConstants.AUTHN_DATA_STREAM_NAME, System.currentTimeMillis(),
                                metadataArray, null, payloadData);
                        AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
                        if (LOG.isDebugEnabled() && event != null) {
                            LOG.debug("Sending out event : " + event.toString());
                        }
                        payloadData[1] = UUID.randomUUID().toString();

                    }
                } finally {
                    FrameworkUtils.endTenantFlow();
                }
            }
        } catch (IdentityRuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Error while publishing authentication data", e);
            }
        }
    }

    @Override
    public String getName() {
        return "TENANT_LOGIN_DATA_PUBLISHER";
    }
}
