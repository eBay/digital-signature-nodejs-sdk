/*
 * *
 *  * Copyright 2022 eBay Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 */

'use strict';

import { Response, Request } from 'express';
import { jwtDecrypt } from 'jose';
import { constants } from '../lib/constants';
import { readKey } from '../lib/helpers/common';
import * as DigitalSignatureSDK from '../lib/index';

const testData = require('./test.json');

describe('test Signature SDK', () => {
    beforeAll(() => {
        Date.now = jest.fn(() => 1663459378000);
    });

    describe('Content-Digest', () => {
        test("should be able to generate for SHA256 cipher", () => {
            const request: string = '{"hello": "world"}';
            const requestBuffer: Buffer = Buffer.from(request);
            const expected: string = 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:';

            const actual = DigitalSignatureSDK.generateDigestHeader(
                requestBuffer, constants.SHA_256);

            expect(actual).toBe(expected);
        });

        test("should be able to generate for SHA512 cipher", () => {
            const request: string = '{"hello": "world"}';
            const requestBuffer: Buffer = Buffer.from(request);
            const expected: string = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:';

            const actual = DigitalSignatureSDK.generateDigestHeader(
                requestBuffer, constants.SHA_512);

            expect(actual).toBe(expected);
        });
    });

    describe('ED25519', () => {
        test("should be able to generate 'signature-input' header when request has payload", () => {
            const config: DigitalSignatureSDK.Config = testData.ED25519;
            const expected: string = `sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=1663459378`;

            const actual = DigitalSignatureSDK.generateSignatureInput({ "content-digest": "test" }, config);

            expect(actual).toBe(expected);
        });

        test("should be able to generate 'signature-input' header when request has no payload", () => {
            const config: DigitalSignatureSDK.Config = testData.ED25519_GET;
            const expected: string = `sig1=("x-ebay-signature-key" "@method" "@path" "@authority");created=1663459378`;

            const actual = DigitalSignatureSDK.generateSignatureInput({ "content-digest": "test" }, config);

            expect(actual).toBe(expected);
        });

        test("should be able to generate 'Signature' header", () => {
            const config: DigitalSignatureSDK.Config = testData.ED25519;
            const expected = 'sig1=:gkk7dqudw21DFHDVBoRUWe/F6/2hTEmWRFDBxiN6COD4PjozXziiDFML1nFHu+0UcMXC/niltxzABjnugu4DCA==:';

            const actual = DigitalSignatureSDK.generateSignature({
                'content-digest': 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
                'signature-input': 'sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=1663459378',
                'x-ebay-signature-key': 'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ'
            }, config);

            expect(actual).toBe(expected);
        });

        test("should be able to generate 'Signature' header with given JWE", () => {
            const config: DigitalSignatureSDK.Config = testData.ED25519_SIGN;
            const expected = 'sig1=:gkk7dqudw21DFHDVBoRUWe/F6/2hTEmWRFDBxiN6COD4PjozXziiDFML1nFHu+0UcMXC/niltxzABjnugu4DCA==:';

            const actual = DigitalSignatureSDK.generateSignature({
                'content-digest': 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
                'signature-input': 'sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=1663459378',
                'x-ebay-signature-key': 'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ'
            }, config);

            expect(actual).toBe(expected);
        });

        test("should be able to generate 'x-ebay-signature-key' header", async () => {
            const actual = await DigitalSignatureSDK.generateSignatureKey(testData.ED25519);

            const masterKey: string = readKey(testData.ED25519.masterKey);
            const masterKeyBuffer: Buffer = Buffer.from(masterKey, constants.BASE64);
            const jwtDecryptResult: any = await jwtDecrypt(actual, masterKeyBuffer)

            expect(jwtDecryptResult.payload.iat).toBe(1663459378);
            expect(jwtDecryptResult.payload.nbf).toBe(1663459378);
            expect(jwtDecryptResult.payload.pkey).toBe('MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=');
            expect(jwtDecryptResult.protectedHeader.alg).toBe('A256GCMKW');
            expect(jwtDecryptResult.protectedHeader.enc).toBe('A256GCM');
            expect(jwtDecryptResult.protectedHeader.zip).toBe('DEF');
        });

        test("should be able to sign a request", async () => {
            const payload: string = '{"hello": "world"}';
            const payloadBuffer: Buffer = Buffer.from(payload);
            const mockedRequest = {
                method: 'POST',
                headers: {
                    host: 'localhost:8080',
                    url: '/test',
                },
                body: payloadBuffer
            } as unknown as Request;

            const mockedResponse = {
                setHeader: jest.fn(),
            } as unknown as Response;

            await DigitalSignatureSDK.signMessage(mockedRequest, mockedResponse, testData.ED25519);

            const signatureSpy = jest.spyOn(mockedResponse, 'setHeader');
            expect(signatureSpy).toHaveBeenCalledWith("content-digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
            expect(signatureSpy).toHaveBeenCalledWith("signature-input", "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1663459378");
            expect(signatureSpy).toHaveBeenCalledWith('signature', expect.any(String));
            expect(signatureSpy).toHaveBeenCalledWith('x-ebay-signature-key', expect.any(String));
        });

        test("should be able to validate request signature", async () => {
            const payload: string = '{"hello": "world"}';
            const payloadBuffer: Buffer = Buffer.from(payload);
            const request = {
                method: 'POST',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'content-digest': 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
                    'signature-input': 'sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=1663544232',
                    'x-ebay-signature-key': 'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJqMDdkYy15U3RGTUdOUGpEIiwidGFnIjoiaFdtYW1vSzFveW5uNXJzQXBkWEZjZyJ9.IJCvc284w_hKPvOKnWOAFnFHmLrp3V-Av3H_m4IbDHw.9kIqPr4zrS7NxDAU.7wh7lhxBFGdkpol3WL9biXWKhtnilkUlSf5lRq2leEwYCJHnShHbwLHuKBkAMs-vzIO8zMEyaim54MCr8-b4I8LRE_8XLmf_Qd4Ir-D-5tIC9DUczGeLMNC_3HCpUXvWM4_gQtMQIqSvEbRrEfw8LJL5w3rYkuzLdA.1ilezim-wzrwYnB8XEJmXA',
                    'signature': 'sig1=:4keDXUAU1iLJsD4+Osx7svHCNjhsozRuO+PsrtXlb2UR8oC6sAaVACrIyn3NITk9kArDZcx7iXaGe69kwHSOBQ==:'
                },
                body: payloadBuffer
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                testData.ED25519
            );

            expect(actual).toBeTruthy();
        });

        test("should generate a valid signature", async () => {
            const payload: string = '{"hello": "world"}';
            const payloadBuffer: Buffer = Buffer.from(payload);
            const config: DigitalSignatureSDK.Config = testData.ED25519;
            const contentDigest = DigitalSignatureSDK.generateDigestHeader(
                payloadBuffer,
                config.digestAlgorithm
            );
            const signatureInput = DigitalSignatureSDK.generateSignatureInput({
                "content-digest": contentDigest
            }, config);
            const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
            const signature = DigitalSignatureSDK.generateSignature({
                'content-digest': contentDigest,
                'signature-input': signatureInput,
                'x-ebay-signature-key': signatureKey
            },
                config
            );

            const request = {
                method: 'POST',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'content-digest': contentDigest,
                    'signature-input': signatureInput,
                    'x-ebay-signature-key': signatureKey,
                    'signature': signature
                },
                body: payloadBuffer
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                testData.ED25519
            );

            expect(actual).toBeTruthy();
        });

        test("should generate a valid signature for GET requests", async () => {
            const config: DigitalSignatureSDK.Config = testData.ED25519_GET;

            const signatureInput = DigitalSignatureSDK.generateSignatureInput({
                "content-digest": "test"
            }, config);
            const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
            const signature = DigitalSignatureSDK.generateSignature({
                'signature-input': signatureInput,
                'x-ebay-signature-key': signatureKey
            },
                config
            );

            const request = {
                method: 'GET',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'signature-input': signatureInput,
                    'x-ebay-signature-key': signatureKey,
                    'signature': signature
                }
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                testData.ED25519_GET
            );

            expect(actual).toBeTruthy();
        });

        test("should work when keys are provided in the config", async () => {
            const payload: string = '{"hello": "world"}';
            const payloadBuffer: Buffer = Buffer.from(payload);
            const config: DigitalSignatureSDK.Config = testData.ED25519_CONFIG_KEYS;
            const contentDigest = DigitalSignatureSDK.generateDigestHeader(
                payloadBuffer,
                config.digestAlgorithm
            );
            const signatureInput = DigitalSignatureSDK.generateSignatureInput({
                "content-digest": contentDigest
            }, config);
            const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
            const signature = DigitalSignatureSDK.generateSignature({
                'content-digest': contentDigest,
                'signature-input': signatureInput,
                'x-ebay-signature-key': signatureKey
            },
                config
            );

            const request = {
                method: 'POST',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'content-digest': contentDigest,
                    'signature-input': signatureInput,
                    'x-ebay-signature-key': signatureKey,
                    'signature': signature
                },
                body: payloadBuffer
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                testData.ED25519_CONFIG_KEYS
            );

            expect(actual).toBeTruthy();
        });
    });

    describe('RSA', () => {
        test("should be able to validate request signature", async () => {
            const payload: string = '{"hello": "world"}';
            const payloadBuffer: Buffer = Buffer.from(payload);
            const request = {
                method: 'POST',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'content-digest': 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
                    'signature-input': 'sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=1664063650',
                    'x-ebay-signature-key': 'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiNk5OVXE0VGNVVWNybzN5dWpoRGFSZyIsImFsZyI6IkEyNTZHQ01LVyIsIml2Ijoia2l1UWdCQ1RfTGZsOWgzZCJ9.3CobfAxjXWlyxidZ_3JtFbkZc2nGxIansMTQa5Yp0io.ZoKTfN2qs8pdZwax.KfnI6Nq2c7wH34ZQvewJ4cMe3HkqLerztnjaCNLFhp6-6bD2TYhdbuiUNN87Fhgbs1qBgtA2SobLCxn_ErpL4VDG2tG1POIjYhESTB27jUIeBvQZRu0qDxOwX5NyjMW6l_Eg43j3FjkyNYTt2sCyvPejTA4gI67RdS5ZMTOJTcsM0GXOftZQDqaCc9Kpu-VQC2Ud20jbWJlO5DMLQtq6bSqfySpy8F5KCW9-96_496veCHp4ioiGRjhdiRFI1BsaqbCnobc83_05zL9syZ_La9zJXzYcOwECDM94yPFIJhhUoMNZY9-H_UxDlHG1VuVaxFy3jDjpl0AEOISybSE6mh60CcHMT9fFtIglV3wp0G4PUZbWzc9ocrOzd-R7MS7eldVPAS1I1Zi1w8GMbbUsyZlef7KnIWMJtJcIGDuebCnYr7r7dQ3QL6hJ9hGYNru0F-NVAwWOd06TB1cG-YQfPoRCBhjLVkrzFIDZvBjsXhW6r_f8GPqJ3BgNjy9f57GA2jPiicvf_h1CNuMCgmIT1sn3dEdD7fiBbX6Vivm4DR-X.uLH9vgGl91WGWNOxNGRt_Q',
                    'signature': 'sig1=:iWm9H9wmE4q7ogqa+6W0tEob45Gf6p59j1wDKc73qkmrZmNHFyhMNuuYpO6HiKhacsrE/+C/QvIZPZaP4+vBtFUN2zvzTFfiG3mPgEojSSx7DfS4jHeftpDoBRrc+7UvolXOukkzIQyKfx3x2Rh8JWdspfP54G472E779mm15LrMTFlURzupY6FUI/DrKFC229xMevSmBSKkMa+MAGTa9k5IIYv6wpHCWNQpow2fdPSjxfli6DeSYCrP5WMY4Ke+g0ads3tVyGXUW39oAmTdWC/SWucGUgBDH14JIZao9mGmQoh/CytsZS1F4HY7zLcDq+Fe1E5JjnJ0K3T9koRHiw==:'
                },
                body: payloadBuffer
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                testData.RSA
            );

            expect(actual).toBeTruthy();
        });

        test("should generate a valid signature", async () => {
            const payload: string = '{"hello": "world"}';
            const payloadBuffer: Buffer = Buffer.from(payload);
            const config: DigitalSignatureSDK.Config = testData.RSA;
            const contentDigest = DigitalSignatureSDK.generateDigestHeader(
                payloadBuffer,
                config.digestAlgorithm
            );
            const signatureInput = DigitalSignatureSDK.generateSignatureInput({
                "content-digest": contentDigest
            }, config);
            const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
            const signature = DigitalSignatureSDK.generateSignature({
                'content-digest': contentDigest,
                'signature-input': signatureInput,
                'x-ebay-signature-key': signatureKey
            },
                config
            );

            const request = {
                method: 'POST',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'content-digest': contentDigest,
                    'signature-input': signatureInput,
                    'x-ebay-signature-key': signatureKey,
                    'signature': signature
                },
                body: payloadBuffer
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                config
            );
        });

        test("should generate a valid signature for GET requests", async () => {
            const config: DigitalSignatureSDK.Config = testData.RSA_GET;

            const signatureInput = DigitalSignatureSDK.generateSignatureInput({}, config);
            const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
            const signature = DigitalSignatureSDK.generateSignature({
                'signature-input': signatureInput,
                'x-ebay-signature-key': signatureKey
            },
                config
            );

            const request = {
                method: 'GET',
                headers: {
                    'host': 'localhost:8080',
                    'url': '/test',
                    'content-type': 'application/json',
                    'signature-input': signatureInput,
                    'x-ebay-signature-key': signatureKey,
                    'signature': signature
                }
            } as unknown as Request;

            const actual: boolean = await DigitalSignatureSDK.validateSignature(
                request,
                config
            );
        });
    });
});

