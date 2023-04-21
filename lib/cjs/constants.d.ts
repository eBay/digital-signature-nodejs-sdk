export declare const constants: {
    readonly BASE64: "base64";
    readonly COLON: ":";
    readonly CONTENT_DIGEST_SHA256: "sha-256=:";
    readonly CONTENT_DIGEST_SHA512: "sha-512=:";
    readonly HEADERS: {
        readonly APPLICATION_JSON: "application/json";
        readonly CONTENT_DIGEST: "content-digest";
        readonly SIGNATURE_INPUT: "signature-input";
        readonly SIGNATURE_KEY: "x-ebay-signature-key";
        readonly SIGNATURE: "signature";
    };
    readonly HTTP_STATUS_CODE: {
        readonly NO_CONTENT: 204;
        readonly OK: 200;
        readonly BAD_REQUEST: 400;
        readonly INTERNAL_SERVER_ERROR: 500;
    };
    readonly KEY_PATTERN_END: RegExp;
    readonly KEY_PATTERN_START: RegExp;
    readonly KEY_END: "\n-----END PUBLIC KEY-----";
    readonly KEY_START: "-----BEGIN PUBLIC KEY-----\n";
    readonly SHA_256: "sha256";
    readonly SHA_512: "sha512";
    readonly SIGNATURE_PREFIX: "sig1=:";
    readonly UTF8: "utf8";
    readonly X_EBAY_SIGNATURE: "x-ebay-signature";
};
