/* global describe, it */
const assert = require('assert');
const ip = require('../lib/ip');

describe('SSRF Vulnerability Tests', () => {
  describe('IPv4 Edge Case Attack Vectors', () => {
    // Test compressed IPv4 formats that should be blocked
    it('should block compressed IPv4 format "127.1"', () => {
      assert.strictEqual(ip.isPublic('127.1'), false, 'Compressed format 127.1 should not be public');
    });

    it('should block compressed IPv4 format "127.0.1"', () => {
      assert.strictEqual(ip.isPublic('127.0.1'), false, 'Compressed format 127.0.1 should not be public');
    });

    it('should block compressed IPv4 format "10.1"', () => {
      assert.strictEqual(ip.isPublic('10.1'), false, 'Compressed format 10.1 should not be public');
    });

    // Test octal notation attacks
    it('should block octal notation "0177.0.0.1"', () => {
      assert.strictEqual(ip.isPublic('0177.0.0.1'), false, 'Octal notation should not be public');
    });

    it('should block octal notation "012.1.2.3"', () => {
      assert.strictEqual(ip.isPublic('012.1.2.3'), false, 'Mixed octal notation should not be public');
    });

    it('should block octal notation "010.0.0.01"', () => {
      assert.strictEqual(ip.isPublic('010.0.0.01'), false, 'Octal notation should not be public');
    });

    // Test hexadecimal notation attacks
    it('should block hexadecimal notation "0x7f.0.0.1"', () => {
      assert.strictEqual(ip.isPublic('0x7f.0.0.1'), false, 'Hex notation should not be public');
    });

    it('should block hexadecimal notation "0x7f.0x0.0x0.0x1"', () => {
      assert.strictEqual(ip.isPublic('0x7f.0x0.0x0.0x1'), false, 'Full hex notation should not be public');
    });

    it('should block mixed hex/decimal "127.00.0x1"', () => {
      assert.strictEqual(ip.isPublic('127.00.0x1'), false, 'Mixed hex/decimal should not be public');
    });

    it('should block mixed hex/decimal "127.0.0x0.1"', () => {
      assert.strictEqual(ip.isPublic('127.0.0x0.1'), false, 'Mixed hex/decimal should not be public');
    });

    // Test single-segment numeric attacks
    it('should block single-segment "2130706433" (127.0.0.1 as int)', () => {
      assert.strictEqual(ip.isPublic('2130706433'), false, 'Single integer should not be public');
    });

    it('should block single-segment "01200034567" (octal)', () => {
      assert.strictEqual(ip.isPublic('01200034567'), false, 'Single octal integer should not be public');
    });

    it('should block single-segment "0x7f000001" (hex)', () => {
      assert.strictEqual(ip.isPublic('0x7f000001'), false, 'Single hex integer should not be public');
    });

    // Test leading zero attacks
    it('should block leading zeros "001.002.003.004"', () => {
      assert.strictEqual(ip.isPublic('001.002.003.004'), false, 'Leading zeros should not be public');
    });

    it('should block mixed leading zeros "127.01.02.03"', () => {
      assert.strictEqual(ip.isPublic('127.01.02.03'), false, 'Mixed leading zeros should not be public');
    });
  });

  describe('IPv6 Edge Case Attack Vectors', () => {
    // Test IPv6 loopback variations
    it('should block IPv6 loopback "::1"', () => {
      assert.strictEqual(ip.isPublic('::1'), false, 'IPv6 loopback should not be public');
    });

    it('should block IPv6 mapped loopback "::ffff:127.0.0.1"', () => {
      assert.strictEqual(ip.isPublic('::ffff:127.0.0.1'), false, 'IPv6 mapped loopback should not be public');
    });

    it('should block ambiguous IPv6 "000:0:0000::01"', () => {
      assert.strictEqual(ip.isPublic('000:0:0000::01'), false, 'Ambiguous IPv6 should not be public');
    });

    it('should block case variation "::fFFf:127.0.0.1"', () => {
      assert.strictEqual(ip.isPublic('::fFFf:127.0.0.1'), false, 'Case variant should not be public');
    });

    it('should block IPv6 zero "::"', () => {
      assert.strictEqual(ip.isPublic('::'), false, 'IPv6 zero should not be public');
    });
  });

  describe('Private Network Attack Vectors', () => {
    // Test private network bypasses
    it('should block private network "192.168.1.1"', () => {
      assert.strictEqual(ip.isPublic('192.168.1.1'), false, 'Private network should not be public');
    });

    it('should block private network "10.0.0.1"', () => {
      assert.strictEqual(ip.isPublic('10.0.0.1'), false, 'Private network should not be public');
    });

    it('should block private network "172.16.0.1"', () => {
      assert.strictEqual(ip.isPublic('172.16.0.1'), false, 'Private network should not be public');
    });

    it('should block link-local "169.254.1.1"', () => {
      assert.strictEqual(ip.isPublic('169.254.1.1'), false, 'Link-local should not be public');
    });
  });

  describe('normalizeToLong Function Security', () => {
    // Test that normalizeToLong rejects dangerous formats
    it('should return -1 for compressed format "127.1"', () => {
      assert.strictEqual(ip.normalizeToLong('127.1'), -1, 'Should reject compressed format');
    });

    it('should return -1 for octal format "0177.0.0.1"', () => {
      assert.strictEqual(ip.normalizeToLong('0177.0.0.1'), -1, 'Should reject octal format');
    });

    it('should return -1 for hex format "0x7f.0.0.1"', () => {
      assert.strictEqual(ip.normalizeToLong('0x7f.0.0.1'), -1, 'Should reject hex format');
    });

    it('should return -1 for leading zero "127.01.02.03"', () => {
      assert.strictEqual(ip.normalizeToLong('127.01.02.03'), -1, 'Should reject leading zeros');
    });

    it('should return -1 for single segment "2130706433"', () => {
      assert.strictEqual(ip.normalizeToLong('2130706433'), -1, 'Should reject single segment');
    });

    it('should return -1 for invalid range "256.1.1.1"', () => {
      assert.strictEqual(ip.normalizeToLong('256.1.1.1'), -1, 'Should reject invalid range');
    });

    it('should return -1 for too many parts "1.2.3.4.5"', () => {
      assert.strictEqual(ip.normalizeToLong('1.2.3.4.5'), -1, 'Should reject too many parts');
    });

    // Test valid formats still work
    it('should accept valid format "127.0.0.1"', () => {
      assert.strictEqual(ip.normalizeToLong('127.0.0.1'), 2130706433, 'Should accept valid format');
    });

    it('should accept valid format "192.168.1.1"', () => {
      assert.strictEqual(ip.normalizeToLong('192.168.1.1'), 3232235777, 'Should accept valid format');
    });

    it('should accept single digit "1.2.3.4"', () => {
      assert.strictEqual(ip.normalizeToLong('1.2.3.4'), 16909060, 'Should accept single digits');
    });

    it('should accept zero "0.0.0.0"', () => {
      assert.strictEqual(ip.normalizeToLong('0.0.0.0'), 0, 'Should accept zero');
    });
  });

  describe('Legitimate Public IP Addresses', () => {
    // Test that legitimate public IPs still work
    it('should allow Google DNS "8.8.8.8"', () => {
      assert.strictEqual(ip.isPublic('8.8.8.8'), true, 'Google DNS should be public');
    });

    it('should allow Cloudflare DNS "1.1.1.1"', () => {
      assert.strictEqual(ip.isPublic('1.1.1.1'), true, 'Cloudflare DNS should be public');
    });

    it('should allow random public IP "203.0.113.1"', () => {
      assert.strictEqual(ip.isPublic('203.0.113.1'), true, 'Public IP should be public');
    });

    it('should allow IPv6 public "2001:4860:4860::8888"', () => {
      assert.strictEqual(ip.isPublic('2001:4860:4860::8888'), true, 'IPv6 public should be public');
    });
  });

  describe('Edge Cases and Malformed Input', () => {
    // Test various malformed inputs
    it('should reject malformed "300.300.300.300"', () => {
      assert.strictEqual(ip.isPublic('300.300.300.300'), false, 'Should reject out-of-range');
    });

    it('should reject malformed "1.2.3"', () => {
      assert.strictEqual(ip.isPublic('1.2.3'), false, 'Should reject incomplete');
    });

    it('should reject malformed "1.2.3.4.5"', () => {
      assert.strictEqual(ip.isPublic('1.2.3.4.5'), false, 'Should reject too many parts');
    });

    it('should reject non-numeric "abc.def.ghi.jkl"', () => {
      assert.strictEqual(ip.isPublic('abc.def.ghi.jkl'), false, 'Should reject non-numeric');
    });

    it('should reject whitespace-only string', () => {
      assert.strictEqual(ip.isPublic('   '), false, 'Should reject whitespace-only string');
    });

    it('should reject undefined input', () => {
      assert.strictEqual(ip.isPublic(undefined), false, 'Should reject undefined');
    });

    it('should reject null input', () => {
      assert.strictEqual(ip.isPublic(null), false, 'Should reject null');
    });

    it('should reject null-like input', () => {
      assert.strictEqual(ip.isPublic('null'), false, 'Should reject null-like');
    });

    it('should reject mixed valid/invalid "192.168.1.abc"', () => {
      assert.strictEqual(ip.isPublic('192.168.1.abc'), false, 'Should reject mixed format');
    });
  });

  describe('SSRF Attack Simulation', () => {
    // Simulate common SSRF attack patterns
    const attackVectors = [
      '127.1',              // Compressed loopback
      '127.0.1',            // Compressed loopback
      '0177.0.0.1',         // Octal loopback
      '0x7f.0.0.1',         // Hex loopback
      '2130706433',         // Integer loopback
      '127.00.0x1',         // Mixed format
      '::ffff:127.0.0.1',   // IPv6 mapped
      '::1',                // IPv6 loopback
      '000:0:0000::01',     // Ambiguous IPv6
      '01200034567',        // Large octal
      '0x7f000001',         // Large hex
      '192.168.1.1',        // Private network
      '10.0.0.1',           // Private network
      '172.16.0.1',         // Private network
      '169.254.1.1'         // Link-local
    ];

    attackVectors.forEach(vector => {
      it(`should block SSRF attack vector "${vector}"`, () => {
        assert.strictEqual(
          ip.isPublic(vector),
          false,
          `Attack vector "${vector}" should not be classified as public`
        );
      });
    });
  });

  describe('Performance and Reliability', () => {
    // Test performance with many iterations
    it('should handle repeated validation efficiently', () => {
      const start = Date.now();
      for (let i = 0; i < 1000; i++) {
        ip.isPublic('127.1');
        ip.isPublic('8.8.8.8');
      }
      const elapsed = Date.now() - start;
      assert(elapsed < 1000, 'Should complete 2000 validations in under 1 second');
    });

    // Test consistency
    it('should return consistent results', () => {
      const testCases = [
        ['127.1', false],
        ['8.8.8.8', true],
        ['192.168.1.1', false],
        ['0x7f.0.0.1', false]
      ];

      testCases.forEach(([input, expected]) => {
        for (let i = 0; i < 10; i++) {
          assert.strictEqual(
            ip.isPublic(input),
            expected,
            `Result should be consistent for "${input}"`
          );
        }
      });
    });
  });
});
