import { Strategy as FBStrategy } from "passport-facebook";
import { v4 as uuidV4 } from "uuid";
import express, { Router } from "express";
import { Authenticator, Profile } from "passport";
import { default as ApiClient } from "@magda/auth-api-client";
import {
    AuthPluginConfig,
    createOrGetUserToken,
    redirectOnSuccess,
    redirectOnError,
    getAbsoluteUrl
} from "@magda/authentication-plugin-sdk";

export interface AuthPluginRouterOptions {
    authorizationApi: ApiClient;
    passport: Authenticator;
    clientId: string;
    clientSecret: string;
    externalUrl: string;
    authPluginRedirectUrl: string;
    authPluginConfig: AuthPluginConfig;
}

export default function createAuthPluginRouter(
    options: AuthPluginRouterOptions
): Router {
    const authorizationApi = options.authorizationApi;
    const passport = options.passport;
    const clientId = options.clientId;
    const clientSecret = options.clientSecret;
    const externalUrl = options.externalUrl;
    const loginBaseUrl = `${externalUrl}/auth/login/plugin`;
    const authPluginConfig = options.authPluginConfig;
    const resultRedirectionUrl = getAbsoluteUrl(
        options.authPluginRedirectUrl,
        externalUrl
    );

    if (!clientId) {
        throw new Error("Required client id can't be empty!");
    }

    if (!clientSecret) {
        throw new Error("Required client secret can't be empty!");
    }

    passport.use(
        new FBStrategy(
            {
                clientID: clientId,
                clientSecret: clientSecret,
                profileFields: ["displayName", "photos", "email"],
                callbackURL: `${loginBaseUrl}/${authPluginConfig.key}/return`
            },
            function (
                accessToken: string,
                refreshToken: string,
                profile: Profile,
                cb: Function
            ) {
                createOrGetUserToken(
                    authorizationApi,
                    { ...profile, provider: authPluginConfig.key },
                    authPluginConfig.key
                )
                    .then((userId) => cb(null, userId))
                    .catch((error) => cb(error));
            }
        )
    );

    const router: express.Router = express.Router();

    router.get("/", (req, res, next) => {
        const redirectUrlId = uuidV4();
        const redirectUrl =
            typeof req?.query?.redirect === "string" && req.query.redirect
                ? getAbsoluteUrl(req.query.redirect, externalUrl)
                : resultRedirectionUrl;
        // save final hop redirect url to session
        (req as any).session[redirectUrlId] = redirectUrl;
        passport.authenticate("facebook", {
            scope: ["public_profile", "email"],
            state: redirectUrlId
        })(req, res, next);
    });

    function getLoginReturnRedirectUrl(req: express.Request) {
        const redirectUrlId = req?.query?.state as string;
        let redirectUrl = redirectUrlId
            ? (req as any)?.session?.[redirectUrlId]
            : undefined;

        // This should not happen. If it happens, do our best.
        if (!redirectUrl) {
            console.log(
                "Unable to find the expected redirect URL. Try the best."
            );
            redirectUrl = options.authPluginRedirectUrl;
        }
        return getAbsoluteUrl(redirectUrl, externalUrl);
    }

    router.get(
        "/return",
        passport.authenticate("facebook", { failWithError: true }),
        (
            req: express.Request,
            res: express.Response,
            next: express.NextFunction
        ) => {
            redirectOnSuccess(getLoginReturnRedirectUrl(req), req, res);
        },
        (
            err: any,
            req: express.Request,
            res: express.Response,
            next: express.NextFunction
        ): any => {
            console.error(err);
            redirectOnError(err, getLoginReturnRedirectUrl(req), req, res);
        }
    );

    return router;
}
