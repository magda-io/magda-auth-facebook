# magda-auth-facebook

![Version: 2.0.0](https://img.shields.io/badge/Version-2.0.0-informational?style=flat-square)

A Magda Auth Plugin for facebook.

Requires MAGDA version 0.0.58 or above.

### How to Use

1. Create a facebook dev account & Register your facebook app at:
https://developers.facebook.com/

- Make sure `Client OAuth login` is enabled
- Set Valid OAuth Redirect URIs to: `https://[external domain]/auth/login/plugin/facebook/return`

> Please note:
> the `[external domain]` should be the external domain that is used to access Magda.
> If you change the auth plugin key, the `facebook` part in the Redirect URIs should be replaced with the new auth plugin key.

2. Add the auth plugin as a [Helm Chart Dependency](https://helm.sh/docs/helm/helm_dependency/)
```yaml
- name: magda-auth-facebook
  version: "2.0.0" # or put latest version number here
  repository: "oci://ghcr.io/magda-io/charts"
```

> Since v2.0.0, we use [Github Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) as our official Helm Chart & Docker Image release registry.

3. Config the auth plugin with required parameters
```yaml
magda-auth-facebook:
  clientId: "xxxxxxx"
```

4. Supply facebook oauth client secret via secret "oauth-secrets" key "facebook-client-secret".

5. Config Gatway to add the auth plugin to Gateway's plugin list (More details see [here](https://github.com/magda-io/magda/blob/master/deploy/helm/internal-charts/gateway/README.md))
```yaml
gateway:
  authPlugins:
  - key: "facebook"
    baseUrl: http://magda-auth-facebook
```

## Requirements

Kubernetes: `>= 1.14.0-0`

| Repository | Name | Version |
|------------|------|---------|
| oci://ghcr.io/magda-io/charts | magda-common | 2.1.1 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| authPluginConfig.authenticationMethod | string | `"IDP-URI-REDIRECTION"` | The authentication method of the plugin. Support values are: <ul> <li>`IDP-URI-REDIRECTION`: the plugin will redirect user agent to idp (identity provider) for authentication. e.g. Google & facebook oauth etc.</li> <li>`PASSWORD`: the plugin expect frontend do a form post that contains username & password to the plugin for authentication.</li> <li>`QR-CODE`: the plugin offers a url that is used by the frontend to request auth challenge data. The data will be encoded into a QR-code image and expect the user scan the QR code with a mobile app to complete the authentication request.</li> </ul> See [Authentication Plugin Specification](https://github.com/magda-io/magda/blob/master/docs/docs/authentication-plugin-spec.md) for more details |
| authPluginConfig.iconUrl | string | `"/icon.svg"` | the display icon URL of the auth plugin. |
| authPluginConfig.key | string | `"facebook"` | the unique key of the auth plugin. Allowed characters: [a-zA-Z0-9\-] |
| authPluginConfig.loginFormExtraInfoContent | string | `""` | Optional; Only applicable when authenticationMethod = "PASSWORD". If present, will displayed the content underneath the login form to provide extra info to users. e.g. how to reset password Can support content in markdown format. |
| authPluginConfig.loginFormExtraInfoHeading | string | `""` | Optional; Only applicable when authenticationMethod = "PASSWORD". If present, will displayed the heading underneath the login form to provide extra info to users. e.g. how to reset password |
| authPluginConfig.loginFormPasswordFieldLabel | string | "Password" | Optional; Only applicable when authenticationMethod = "PASSWORD". |
| authPluginConfig.loginFormUsernameFieldLabel | string | "Username" | Optional; Only applicable when authenticationMethod = "PASSWORD". |
| authPluginConfig.name | string | `"Facebook"` | the display name of the auth plugin. |
| authPluginConfig.qrCodeAuthResultPollUrl | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". The url that is used by frontend to poll the authentication processing result. See [Authentication Plugin Specification](https://github.com/magda-io/magda/blob/master/docs/docs/authentication-plugin-spec.md) for more details |
| authPluginConfig.qrCodeExtraInfoContent | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". If present, will displayed the content underneath the login form to provide extra info to users. e.g. how to download moile app to scan the QR Code. Can support content in markdown format. |
| authPluginConfig.qrCodeExtraInfoHeading | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". If present, will displayed the heading underneath the QR Code image to provide extra instruction to users. e.g. how to download moile app to scan the QR Code |
| authPluginConfig.qrCodeImgDataRequestUrl | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". The url that is used by frontend client to request auth challenge data from the authentication plugin. See [Authentication Plugin Specification](https://github.com/magda-io/magda/blob/master/docs/docs/authentication-plugin-spec.md) for more details |
| authPluginRedirectUrl | string | `nil` | the redirection url after the whole authentication process is completed. Authentication Plugins will use this value as default. The following query parameters can be used to supply the authentication result: <ul> <li>result: (string) Compulsory. Possible value: "success" or "failure". </li> <li>errorMessage: (string) Optional. Text message to provide more information on the error to the user. </li> </ul> This field is for overriding the value set by `global.authPluginRedirectUrl`. Unless you want to have a different value only for this auth plugin, you shouldn't set this value. |
| autoscaler.enabled | bool | `false` | turn on the autoscaler or not |
| autoscaler.maxReplicas | int | `3` |  |
| autoscaler.minReplicas | int | `1` |  |
| autoscaler.targetCPUUtilizationPercentage | int | `80` |  |
| clientId | string | `""` | The client ID for Facebook OAuth. client secret should be passed via secret `oauth-secrets` key `facebook-client-secret` |
| defaultAdminUserId | string | `"00000000-0000-4000-8000-000000000000"` | which system account we used to talk to auth api The value of this field will only be used when `global.defaultAdminUserId` has no value |
| defaultImage.imagePullSecret | bool | `false` |  |
| defaultImage.pullPolicy | string | `"IfNotPresent"` |  |
| defaultImage.repository | string | `"ghcr.io/magda-io"` |  |
| global | object | `{"authPluginRedirectUrl":"/sign-in-redirect","externalUrl":"","image":{},"rollingUpdate":{}}` | only for providing appropriate default value for helm lint |
| image.name | string | `"magda-auth-facebook"` |  |
| replicas | int | `1` | no. of initial replicas |
| resources.limits.cpu | string | `"50m"` |  |
| resources.requests.cpu | string | `"10m"` |  |
| resources.requests.memory | string | `"30Mi"` |  |
