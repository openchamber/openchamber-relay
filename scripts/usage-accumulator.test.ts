// Unit tests for the D1 usage accumulator logic. Run with:
//   bun test apps/relay/scripts/usage-accumulator.test.ts
//
// Verifies the three properties the D1 pipeline depends on:
//   1. delta accumulation (bytes add, peak takes max)
//   2. reset-on-success / keep-on-failure retention, with an explicit drop past the cap
//   3. the additive-UPSERT math (two flushes accumulate; peak takes max)

import { describe, expect, test } from 'bun:test';
import {
  applyUsageUpsert,
  isUsageDeltaEmpty,
  nextPendingAfterFlush,
  recordConnect,
  recordFrameDown,
  recordFrameUp,
  recordMessage,
  utcUsageDate,
  zeroUsageDelta,
  type UsageRow,
} from '../src/core/usage-accumulator';

const CAP = 512 * 1024 * 1024;

describe('delta accumulation', () => {
  test('frames add bytes in each direction; peak takes max on connect', () => {
    const d = zeroUsageDelta();
    expect(isUsageDeltaEmpty(d)).toBe(true);

    recordFrameUp(d, 100);
    recordFrameUp(d, 50);
    recordFrameDown(d, 200);
    recordConnect(d, 3);
    recordConnect(d, 2); // lower concurrency must not lower the peak

    expect(d.bytesUp).toBe(150);
    expect(d.bytesDown).toBe(200);
    expect(d.clientConnects).toBe(2);
    expect(d.peakConcurrentClients).toBe(3);
    expect(isUsageDeltaEmpty(d)).toBe(false);
  });
});

describe('retention after flush', () => {
  test('success zeros the pending delta', () => {
    const d = zeroUsageDelta();
    recordFrameUp(d, 1000);
    const { pending, dropped } = nextPendingAfterFlush(d, true, CAP);
    expect(dropped).toBe(false);
    expect(isUsageDeltaEmpty(pending)).toBe(true);
  });

  test('failure under cap keeps the delta for retry', () => {
    const d = zeroUsageDelta();
    recordFrameUp(d, 1000);
    recordFrameDown(d, 2000);
    recordConnect(d, 4);
    const { pending, dropped } = nextPendingAfterFlush(d, false, CAP);
    expect(dropped).toBe(false);
    expect(pending.bytesUp).toBe(1000);
    expect(pending.bytesDown).toBe(2000);
    expect(pending.clientConnects).toBe(1);
    expect(pending.peakConcurrentClients).toBe(4);
  });

  test('failure over cap drops explicitly', () => {
    const d = zeroUsageDelta();
    recordFrameUp(d, CAP);
    recordFrameDown(d, 1);
    const { pending, dropped } = nextPendingAfterFlush(d, false, CAP);
    expect(dropped).toBe(true);
    expect(isUsageDeltaEmpty(pending)).toBe(true);
  });
});

describe('additive UPSERT math', () => {
  test('two flushes accumulate; peak takes max', () => {
    const start: UsageRow = {
      bytesUp: 0,
      bytesDown: 0,
      clientConnects: 0,
      peakConcurrentClients: 0,
      messages: 0,
    };

    const first = zeroUsageDelta();
    recordFrameUp(first, 500);
    recordFrameDown(first, 700);
    recordConnect(first, 5);
    recordMessage(first);
    recordMessage(first);
    const afterFirst = applyUsageUpsert(start, first);

    const second = zeroUsageDelta();
    recordFrameUp(second, 300);
    recordFrameDown(second, 100);
    recordConnect(second, 2); // lower than the running peak of 5
    recordMessage(second);
    const afterSecond = applyUsageUpsert(afterFirst, second);

    expect(afterSecond.bytesUp).toBe(800);
    expect(afterSecond.bytesDown).toBe(800);
    expect(afterSecond.clientConnects).toBe(2);
    expect(afterSecond.peakConcurrentClients).toBe(5); // MAX, not sum
    expect(afterSecond.messages).toBe(3); // additive: 2 + 1

    // A later flush with a higher peak raises it.
    const third = zeroUsageDelta();
    recordConnect(third, 9);
    const afterThird = applyUsageUpsert(afterSecond, third);
    expect(afterThird.peakConcurrentClients).toBe(9);
    expect(afterThird.clientConnects).toBe(3);
  });
});

describe('utcUsageDate', () => {
  test('returns UTC YYYY-MM-DD', () => {
    expect(utcUsageDate(Date.UTC(2026, 6, 8, 23, 59))).toBe('2026-07-08');
    expect(utcUsageDate(Date.UTC(2026, 0, 1, 0, 0))).toBe('2026-01-01');
  });
});
