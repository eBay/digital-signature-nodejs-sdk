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

import * as fs from 'fs';
import { constants } from "../constants";

function needsContentDigestValidation(requestBody: string): boolean {
    return requestBody !== null &&
        requestBody !== undefined &&
        requestBody.length > 0;
}

function readKey(value: string): string {
    let key: string = value;

    if (fs.existsSync(value)) {
        key = fs.readFileSync(
            value, {
            encoding: constants.UTF8
        });
    }

    return key;
}

export { needsContentDigestValidation, readKey };
