/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  createHmacIdLabelMapFunction
} from '@digitalbazaar/di-sd-primitives';

export function createShuffledIdLabelMapFunction({hmac} = {}) {
  // the second step from the spec produces the same `bnodeIdMap` as
  // the one used in `createHmacIdLabelMapFunction` from ecdsa-sd-2023, so
  // that is reused below;
  const hmacIdLabelFunction = createHmacIdLabelMapFunction({hmac});
  return async ({canonicalIdMap}) => {
    const bnodeIdMap = hmacIdLabelFunction({canonicalIdMap});
    const hmacIds = [...bnodeIdMap.values()].sort();
    const bnodeKeys = [...bnodeIdMap.keys()];
    for(const key of bnodeKeys) {
      bnodeIdMap.set(key, 'b' + hmacIds.indexOf(bnodeIdMap.get(key)));
    }
    return bnodeIdMap;
  };
}
