import { Request, Response } from 'express';
import { generateDigestHeader, validateDigestHeader } from './helpers/digest-helper';
import { generateSignature, generateSignatureInput, generateSignatureKey, validateSignatureHeader } from './helpers/signature-helper';
import { Config } from './types/Config';
/**
 * Generate signature headers and add it to the response.
 *
 * @param {Request} request The request object.
 * @param {Response} response The response object
 * @param {Config} config The input config.
 */
declare function signMessage(request: Request, response: Response, config: Config): Promise<void>;
/**
 * Verifies the signature header for the given request
 *
 * @param {Request} request The request object.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * */
declare function validateSignature(request: Request, config: Config): Promise<boolean>;
export { generateDigestHeader, generateSignature, generateSignatureInput, generateSignatureKey, signMessage, validateDigestHeader, validateSignature, validateSignatureHeader, Config };
