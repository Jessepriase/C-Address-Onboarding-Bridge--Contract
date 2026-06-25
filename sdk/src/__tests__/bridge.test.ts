import { OnboardingBridgeSDK } from '../bridge';
import { SorobanRpc, scValToNative } from '@stellar/stellar-sdk';

jest.mock('@stellar/stellar-sdk', () => ({
  SorobanRpc: {
    Server: jest.fn(),
  },
  Contract: jest.fn().mockImplementation(() => ({
    call: jest.fn().mockReturnValue({}),
  })),
  TransactionBuilder: jest.fn().mockImplementation(() => ({
    addOperation: jest.fn().mockReturnThis(),
    setTimeout: jest.fn().mockReturnThis(),
    build: jest.fn().mockReturnValue({}),
  })),
  Account: jest.fn().mockImplementation(() => ({})),
  xdr: {
    ScVal: {
      scvVoid: jest.fn().mockReturnValue({}),
      scvVec: jest.fn().mockReturnValue({}),
    },
  },
  Address: jest.fn().mockImplementation(() => ({
    toScVal: jest.fn().mockReturnValue({}),
  })),
  nativeToScVal: jest.fn().mockReturnValue({}),
  scValToNative: jest.fn(),
  BASE_FEE: '100',
  Networks: {
    TESTNET: 'Test SDF Network ; September 2015',
    PUBLIC: 'Public Global Stellar Network ; September 2015',
  },
}));

const CONFIG = {
  contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4',
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
};

const MOCK_ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const MOCK_ASSET = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4';

describe('OnboardingBridgeSDK', () => {
  let sdk: OnboardingBridgeSDK;
  let mockProvider: any;
  let mockKeypair: any;

  beforeEach(() => {
    jest.clearAllMocks();

    mockKeypair = {
      publicKey: jest.fn().mockReturnValue(MOCK_ADDRESS),
      sign: jest.fn(),
    };

    mockProvider = {
      getAccount: jest.fn().mockResolvedValue({}),
      prepareTransaction: jest.fn().mockResolvedValue({ sign: jest.fn() }),
      sendTransaction: jest.fn().mockResolvedValue({ hash: 'mock_tx_hash', status: 'PENDING' }),
      simulateTransaction: jest.fn().mockResolvedValue({}),
    };

    (SorobanRpc.Server as jest.Mock).mockImplementation(() => mockProvider);
    sdk = new OnboardingBridgeSDK(CONFIG);
  });

  describe('fundCAddress', () => {
    it('returns pending status on success', async () => {
      const result = await sdk.fundCAddress(
        { source: MOCK_ADDRESS, target: MOCK_ADDRESS, asset: MOCK_ASSET, amount: '1000' },
        mockKeypair,
      );

      expect(result.status).toBe('pending');
      expect(result.hash).toBe('mock_tx_hash');
      expect(mockProvider.getAccount).toHaveBeenCalledWith(MOCK_ADDRESS);
      expect(mockProvider.prepareTransaction).toHaveBeenCalled();
      expect(mockProvider.sendTransaction).toHaveBeenCalled();
    });

    it('returns failed status on ERROR response', async () => {
      mockProvider.sendTransaction.mockResolvedValue({ hash: 'err_hash', status: 'ERROR' });

      const result = await sdk.fundCAddress(
        { source: MOCK_ADDRESS, target: MOCK_ADDRESS, asset: MOCK_ASSET, amount: '1000' },
        mockKeypair,
      );

      expect(result.status).toBe('failed');
      expect(result.hash).toBe('err_hash');
    });

    it('returns failed status on network error', async () => {
      mockProvider.getAccount.mockRejectedValue(new Error('Network timeout'));

      const result = await sdk.fundCAddress(
        { source: MOCK_ADDRESS, target: MOCK_ADDRESS, asset: MOCK_ASSET, amount: '1000' },
        mockKeypair,
      );

      expect(result.status).toBe('failed');
      expect(result.error).toBe('Network timeout');
      expect(result.hash).toBe('');
    });
  });

  describe('batchFundCAddresses', () => {
    it('returns pending status on success', async () => {
      const result = await sdk.batchFundCAddresses(
        {
          source: MOCK_ADDRESS,
          targets: [MOCK_ADDRESS, MOCK_ADDRESS],
          amounts: ['500', '500'],
          asset: MOCK_ASSET,
        },
        mockKeypair,
      );

      expect(result.status).toBe('pending');
      expect(result.hash).toBe('mock_tx_hash');
    });

    it('returns failed status when transaction errors (e.g. mismatched arrays on-chain)', async () => {
      mockProvider.sendTransaction.mockResolvedValue({ hash: 'err_hash', status: 'ERROR' });

      const result = await sdk.batchFundCAddresses(
        {
          source: MOCK_ADDRESS,
          targets: [MOCK_ADDRESS],
          amounts: ['500', '500'],
          asset: MOCK_ASSET,
        },
        mockKeypair,
      );

      expect(result.status).toBe('failed');
    });
  });

  describe('withdrawFees', () => {
    it('returns pending status on success', async () => {
      const result = await sdk.withdrawFees(
        { asset: MOCK_ASSET, amount: '100' },
        mockKeypair,
      );

      expect(result.status).toBe('pending');
      expect(result.hash).toBe('mock_tx_hash');
      expect(mockProvider.getAccount).toHaveBeenCalledWith(MOCK_ADDRESS);
    });
  });

  describe('setFee', () => {
    it('returns pending status on success', async () => {
      const result = await sdk.setFee(100, mockKeypair);

      expect(result.status).toBe('pending');
      expect(mockProvider.getAccount).toHaveBeenCalledWith(MOCK_ADDRESS);
    });
  });

  describe('setFeeCollector', () => {
    it('returns pending status on success', async () => {
      const result = await sdk.setFeeCollector(MOCK_ADDRESS, mockKeypair);

      expect(result.status).toBe('pending');
    });
  });

  describe('setAdmin', () => {
    it('returns pending status on success', async () => {
      const result = await sdk.setAdmin(MOCK_ADDRESS, mockKeypair);

      expect(result.status).toBe('pending');
    });
  });

  describe('getFee', () => {
    it('returns the fee as a number from simulation result', async () => {
      (scValToNative as jest.Mock).mockReturnValue(50);
      mockProvider.simulateTransaction.mockResolvedValue({
        results: [{ retval: {} }],
      });

      const fee = await sdk.getFee();

      expect(fee).toBe(50);
      expect(mockProvider.simulateTransaction).toHaveBeenCalled();
    });

    it('returns 0 when no results are present', async () => {
      mockProvider.simulateTransaction.mockResolvedValue({});

      const fee = await sdk.getFee();

      expect(fee).toBe(0);
    });

    it('throws when simulation returns an error', async () => {
      mockProvider.simulateTransaction.mockResolvedValue({ error: 'contract error' });

      await expect(sdk.getFee()).rejects.toThrow('Failed to get fee');
    });
  });

  describe('getFeeCollector', () => {
    it('returns fee collector address string', async () => {
      (scValToNative as jest.Mock).mockReturnValue({ toString: () => MOCK_ADDRESS });
      mockProvider.simulateTransaction.mockResolvedValue({
        results: [{ retval: {} }],
      });

      const addr = await sdk.getFeeCollector();

      expect(addr).toBe(MOCK_ADDRESS);
    });

    it('returns empty string when no results', async () => {
      mockProvider.simulateTransaction.mockResolvedValue({});

      const addr = await sdk.getFeeCollector();

      expect(addr).toBe('');
    });
  });

  describe('getAdmin', () => {
    it('returns admin address string', async () => {
      (scValToNative as jest.Mock).mockReturnValue({ toString: () => MOCK_ADDRESS });
      mockProvider.simulateTransaction.mockResolvedValue({
        results: [{ retval: {} }],
      });

      const addr = await sdk.getAdmin();

      expect(addr).toBe(MOCK_ADDRESS);
    });

    it('returns empty string when no results', async () => {
      mockProvider.simulateTransaction.mockResolvedValue({});

      const addr = await sdk.getAdmin();

      expect(addr).toBe('');
    });
  });

  describe('getCAddressBalance', () => {
    it('returns balance as a string', async () => {
      (scValToNative as jest.Mock).mockReturnValue({ toString: () => '1000' });
      mockProvider.simulateTransaction.mockResolvedValue({
        results: [{ retval: {} }],
      });

      const balance = await sdk.getCAddressBalance(MOCK_ADDRESS, MOCK_ASSET);

      expect(balance).toBe('1000');
    });

    it('returns "0" when no results', async () => {
      mockProvider.simulateTransaction.mockResolvedValue({});

      const balance = await sdk.getCAddressBalance(MOCK_ADDRESS, MOCK_ASSET);

      expect(balance).toBe('0');
    });
  });

  describe('isInitialized', () => {
    it('returns true when contract is initialized', async () => {
      (scValToNative as jest.Mock).mockReturnValue(true);
      mockProvider.simulateTransaction.mockResolvedValue({
        results: [{ retval: {} }],
      });

      const result = await sdk.isInitialized();

      expect(result).toBe(true);
    });

    it('returns false when no results', async () => {
      mockProvider.simulateTransaction.mockResolvedValue({});

      const result = await sdk.isInitialized();

      expect(result).toBe(false);
    });
  });
});
