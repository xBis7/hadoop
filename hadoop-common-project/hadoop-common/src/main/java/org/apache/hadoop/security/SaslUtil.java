/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.security;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_RPC_SECURITY_CRYPTO_CIPHER_KEY_BITLENGTH_DEFAULT;
import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_RPC_SECURITY_CRYPTO_CIPHER_KEY_BITLENGTH_KEY;
import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_RPC_SECURITY_CRYPTO_CIPHER_SUITES;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.CipherOption;
import org.apache.hadoop.crypto.CipherSuite;
import org.apache.hadoop.crypto.CryptoCodec;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

/**
 * Utility methods implementing SASL negotiation.
 */
@InterfaceAudience.Private
public final class SaslUtil {

  private SaslUtil() {
    /** Hidden constructor */
  }

  /**
   * Check whether requested SASL Qop contains privacy.
   *
   * @param saslProps Qop properties of SASL negotiation
   * @return boolean true if privacy exists
   */
  public static boolean requestedQopContainsPrivacy(
      Map<String, String> saslProps) {
    Set<String> requestedQop =
        ImmutableSet.copyOf(Arrays.asList(saslProps.get(Sasl.QOP).split(",")));
    return requestedQop
        .contains(SaslRpcServer.QualityOfProtection.PRIVACY.getSaslQop());
  }

  /**
   * After successful SASL negotiation, returns whether it's QOP privacy.
   *
   * @return boolean whether it's QOP privacy
   */
  public static boolean isNegotiatedQopPrivacy(SaslServer saslServer) {
    String qop = (String) saslServer.getNegotiatedProperty(Sasl.QOP);
    return qop != null && SaslRpcServer.QualityOfProtection.PRIVACY
        .getSaslQop().equalsIgnoreCase(qop);
  }

  /**
   * After successful SASL negotiation, returns whether it's QOP privacy.
   *
   * @return boolean whether it's QOP privacy
   */
  public static boolean isNegotiatedQopPrivacy(SaslClient saslClient) {
    String qop = (String) saslClient.getNegotiatedProperty(Sasl.QOP);
    return qop != null && SaslRpcServer.QualityOfProtection.PRIVACY
        .getSaslQop().equalsIgnoreCase(qop);
  }

  /**
   * Negotiate a cipher option which server supports.
   *
   * @param conf the configuration
   * @param options the cipher options which client supports
   * @return CipherOption negotiated cipher option
   */
  public static CipherOption negotiateCipherOption(Configuration conf,
      List<CipherOption> options) throws IOException {
    // Negotiate cipher suites if configured.  Currently, the only supported
    // cipher suite is AES/CTR/NoPadding, but the protocol allows multiple
    // values for future expansion.
    String cipherSuites = conf.get(HADOOP_RPC_SECURITY_CRYPTO_CIPHER_SUITES);
    if (cipherSuites == null || cipherSuites.isEmpty()) {
      return null;
    }
    if (!cipherSuites.equals(CipherSuite.AES_CTR_NOPADDING.getName())) {
      throw new IOException(String.format("Invalid cipher suite, %s=%s",
          HADOOP_RPC_SECURITY_CRYPTO_CIPHER_SUITES, cipherSuites));
    }
    if (options != null) {
      for (CipherOption option : options) {
        CipherSuite suite = option.getCipherSuite();
        if (suite == CipherSuite.AES_CTR_NOPADDING) {
          int keyLen = conf.getInt(
              HADOOP_RPC_SECURITY_CRYPTO_CIPHER_KEY_BITLENGTH_KEY,
              HADOOP_RPC_SECURITY_CRYPTO_CIPHER_KEY_BITLENGTH_DEFAULT) / 8;
          CryptoCodec codec = CryptoCodec.getInstance(conf, suite);
          byte[] inKey = new byte[keyLen];
          byte[] inIv = new byte[suite.getAlgorithmBlockSize()];
          byte[] outKey = new byte[keyLen];
          byte[] outIv = new byte[suite.getAlgorithmBlockSize()];
          assert codec != null;
          codec.generateSecureRandom(inKey);
          codec.generateSecureRandom(inIv);
          codec.generateSecureRandom(outKey);
          codec.generateSecureRandom(outIv);
          return new CipherOption(suite, inKey, inIv, outKey, outIv);
        }
      }
    }
    return null;
  }

  /**
   * Encrypt the key of the negotiated cipher option.
   *
   * @param option negotiated cipher option
   * @param saslServer SASL server
   * @return CipherOption negotiated cipher option which contains the
   * encrypted key and iv
   * @throws IOException for any error
   */
  public static CipherOption wrap(CipherOption option, SaslServer saslServer)
      throws IOException {
    if (option != null) {
      byte[] inKey = option.getInKey();
      if (inKey != null) {
        inKey = saslServer.wrap(inKey, 0, inKey.length);
      }
      byte[] outKey = option.getOutKey();
      if (outKey != null) {
        outKey = saslServer.wrap(outKey, 0, outKey.length);
      }
      return new CipherOption(option.getCipherSuite(), inKey, option.getInIv(),
          outKey, option.getOutIv());
    }

    return null;
  }

  /**
   * Decrypt the key of the negotiated cipher option.
   *
   * @param option negotiated cipher option
   * @param saslClient SASL client
   * @return CipherOption negotiated cipher option which contains the
   * decrypted key and iv
   * @throws SaslException for any error
   */
  public static CipherOption unwrap(CipherOption option, SaslClient saslClient)
      throws SaslException {
    if (option != null) {
      byte[] inKey = option.getInKey();
      if (inKey != null) {
        inKey = saslClient.unwrap(inKey, 0, inKey.length);
      }
      byte[] outKey = option.getOutKey();
      if (outKey != null) {
        outKey = saslClient.unwrap(outKey, 0, outKey.length);
      }
      return new CipherOption(option.getCipherSuite(), inKey, option.getInIv(),
          outKey, option.getOutIv());
    }

    return null;
  }

  /**
   * Get the cipher options supported.
   *
   * @param conf the configuration
   * @return List<CipherOption> of the cipher options supported
   */
  public static List<CipherOption> getCipherOptions(Configuration conf)
      throws IOException {
    List<CipherOption> cipherOptions = null;
    String cipherSuites = conf.get(HADOOP_RPC_SECURITY_CRYPTO_CIPHER_SUITES);
    // Negotiate cipher suites if configured.  Currently, the only supported
    // cipher suite is AES/CTR/NoPadding, but the protocol allows multiple
    // values for future expansion.
    if (cipherSuites != null && !cipherSuites.isEmpty()) {
      if (!cipherSuites.equals(CipherSuite.AES_CTR_NOPADDING.getName())) {
        throw new IOException(String.format("Invalid cipher suite, %s=%s",
            HADOOP_RPC_SECURITY_CRYPTO_CIPHER_SUITES, cipherSuites));
      }
      cipherOptions = Lists.newArrayListWithCapacity(1);
      for (String cipherSuite : Splitter.on(',').trimResults().
          omitEmptyStrings().split(cipherSuites)) {
        CipherOption option = new CipherOption(
            CipherSuite.convert(cipherSuite));
        cipherOptions.add(option);
      }
    }
    return cipherOptions;
  }
}
