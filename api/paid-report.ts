import { createMerchant } from '../src/mpp-merchant.js';

export default {
  async fetch(request: Request) {
    try {
      const key = process.env.STRIPE_TEST_SECRET_KEY ?? '';
      const profile = process.env.STRIPE_TEST_PROFILE_ID ?? '';
      return await createMerchant(key, profile)(request);
    } catch {
      return Response.json({ error: 'merchant_unavailable', test_mode: true }, { status: 503, headers: { 'cache-control': 'no-store' } });
    }
  },
};
