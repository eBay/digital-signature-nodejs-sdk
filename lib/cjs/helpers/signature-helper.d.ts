import { Config } from '..';
/**
 * Generates the x-ebay-signature-key header value for the input payload.
 *
 * @param {Config} config The input config.
 * @returns <Promise<string> The signature key value.
 */
declare function generateSignatureKey(config: Config): Promise<string>;
/**
 * Generates the Signature-Input header value for the input payload.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns {string} the 'Signature-Input' header value.
 */
declare function generateSignatureInput(headers: any, config: Config): string;
/**
 * Generates the 'Signature' header.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns {string} the signature header value.
 */
declare function generateSignature(headers: any, config: Config): string;
/**
 * Validates the input signature key (x-ebay-signature-key header value).
 *
 * @param {string} signatureKey the x-ebay-signature-key header value.
 * @param {Config} config The input config.
 * @returns Promise<string> the public key (pkey) value from JWT claims set.
 * @throws {Error} if the header generation fails.
 */
declare function validateSignatureKey(signatureKey: string, config: Config): Promise<string | undefined>;
/**
 * Validates the signature header value.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * @throws Error if the Signature value is invalid.
 */
declare function validateSignatureHeader(headers: any, config: Config): Promise<boolean>;
export { generateSignature, generateSignatureInput, generateSignatureKey, validateSignatureKey, validateSignatureHeader };
