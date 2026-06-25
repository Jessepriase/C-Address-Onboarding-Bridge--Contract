import { OffRampIntegration } from '../offramp';

const TARGET_C_ADDRESS = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4';

describe('OffRampIntegration', () => {
  describe('getMoonpayUrl', () => {
    it('returns a production URL with correct params', () => {
      const offramp = new OffRampIntegration({
        moonpayApiKey: 'test_api_key',
        testMode: false,
      });

      const url = offramp.getMoonpayUrl({
        targetCAddress: TARGET_C_ADDRESS,
        amount: '100',
        currency: 'xlm',
      });

      expect(url).toContain('https://buy.moonpay.com');
      expect(url).toContain('apiKey=test_api_key');
      expect(url).toContain('currency=xlm');
      expect(url).toContain('baseCurrencyAmount=100');
      expect(url).toContain(encodeURIComponent(TARGET_C_ADDRESS));
    });

    it('returns a staging URL when testMode is true', () => {
      const offramp = new OffRampIntegration({
        moonpayApiKey: 'pk_test_123',
        testMode: true,
      });

      const url = offramp.getMoonpayUrl({
        targetCAddress: TARGET_C_ADDRESS,
        amount: '50',
        currency: 'usd',
      });

      expect(url).toContain('https://buy-staging.moonpay.com');
    });

    it('includes assetCode when provided', () => {
      const offramp = new OffRampIntegration({
        moonpayApiKey: 'key',
        testMode: false,
      });

      const url = offramp.getMoonpayUrl({
        targetCAddress: TARGET_C_ADDRESS,
        amount: '200',
        currency: 'xlm',
        assetCode: 'xlm',
      });

      expect(url).toContain('baseCurrencyCode=xlm');
    });
  });

  describe('getTransakUrl', () => {
    it('returns a production URL with correct params', () => {
      const offramp = new OffRampIntegration({
        transakApiKey: 'transak_key',
        testMode: false,
      });

      const url = offramp.getTransakUrl({
        targetCAddress: TARGET_C_ADDRESS,
        amount: '150',
        currency: 'xlm',
      });

      expect(url).toContain('https://global.transak.com');
      expect(url).toContain('apiKey=transak_key');
      expect(url).toContain('defaultCryptoCurrency=XLM');
      expect(url).toContain('network=stellar');
      expect(url).toContain('defaultFiatAmount=150');
    });

    it('returns a staging URL when testMode is true', () => {
      const offramp = new OffRampIntegration({
        transakApiKey: 'key',
        testMode: true,
      });

      const url = offramp.getTransakUrl({
        targetCAddress: TARGET_C_ADDRESS,
        amount: '50',
        currency: 'xlm',
      });

      expect(url).toContain('https://global-staging.transak.com');
    });

    it('includes fiatCurrency when provided', () => {
      const offramp = new OffRampIntegration({
        transakApiKey: 'key',
        testMode: false,
      });

      const url = offramp.getTransakUrl({
        targetCAddress: TARGET_C_ADDRESS,
        amount: '100',
        currency: 'xlm',
        fiatCurrency: 'EUR',
      });

      expect(url).toContain('fiatCurrency=EUR');
    });
  });

  describe('generateCEXDepositMemo', () => {
    it('returns memo in bridge:<address> format', () => {
      const offramp = new OffRampIntegration({});

      const memo = offramp.generateCEXDepositMemo(TARGET_C_ADDRESS);

      expect(memo).toBe(`bridge:${TARGET_C_ADDRESS}`);
    });

    it('always prefixes with bridge:', () => {
      const offramp = new OffRampIntegration({});
      const addr = 'GSOME_ADDRESS';

      const memo = offramp.generateCEXDepositMemo(addr);

      expect(memo.startsWith('bridge:')).toBe(true);
      expect(memo).toBe('bridge:GSOME_ADDRESS');
    });
  });

  describe('decodeCEXDepositMemo', () => {
    it('decodes a valid bridge memo', () => {
      const offramp = new OffRampIntegration({});

      const decoded = offramp.decodeCEXDepositMemo(`bridge:${TARGET_C_ADDRESS}`);

      expect(decoded).toBe(TARGET_C_ADDRESS);
    });

    it('returns null for an invalid memo', () => {
      const offramp = new OffRampIntegration({});

      expect(offramp.decodeCEXDepositMemo('invalid_memo')).toBeNull();
      expect(offramp.decodeCEXDepositMemo('')).toBeNull();
      expect(offramp.decodeCEXDepositMemo('nobridge:addr')).toBeNull();
    });
  });
});
