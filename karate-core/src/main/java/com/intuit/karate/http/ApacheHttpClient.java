/*
 * The MIT License
 *
 * Copyright 2022 Karate Labs Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.intuit.karate.http;

import com.intuit.karate.Constants;
import com.intuit.karate.FileUtils;
import com.intuit.karate.Logger;
import com.intuit.karate.core.Config;
import com.intuit.karate.core.ScenarioEngine;
import io.netty.handler.codec.http.cookie.ClientCookieDecoder;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.cookie.CookieOrigin;
import org.apache.hc.client5.http.cookie.CookieSpecFactory;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.cookie.MalformedCookieException;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpMessage;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.EntityBuilder;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.http.conn.ssl.LenientSslConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.routing.SystemDefaultRoutePlanner;
import org.apache.hc.client5.http.impl.cookie.CookieSpecBase;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;

/**
 *
 * @author pthomas3
 */
public class ApacheHttpClient implements HttpClient, HttpRequestInterceptor {

    private final ScenarioEngine engine;
    private final Logger logger;
    private final HttpLogger httpLogger;

    private HttpClientBuilder clientBuilder;
    private CookieStore cookieStore;

        public static class LenientCookieSpec extends CookieSpecBase {

        static final String KARATE = "karate";

        public LenientCookieSpec() {
            super();
        }

        public static Registry<CookieSpecFactory> registry() {
            CookieSpecFactory specProvider = (HttpContext hc) -> new LenientCookieSpec();
            return RegistryBuilder.<CookieSpecFactory>create()
                    .register(KARATE, specProvider).build();
        }

            @Override
            public List<Cookie> parse(Header header, CookieOrigin cookieOrigin) throws MalformedCookieException {
                return null;
            }

            @Override
            public List<Header> formatCookies(List<Cookie> list) {
                return null;
            }
        }

    public ApacheHttpClient(ScenarioEngine engine) {
        this.engine = engine;
        logger = engine.logger;
        httpLogger = new HttpLogger(logger);
        configure(engine.getConfig());
    }

    private void configure(Config config) {
        PoolingHttpClientConnectionManagerBuilder connectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create();

        clientBuilder = HttpClientBuilder.create();
        clientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build());
        clientBuilder.disableAutomaticRetries();
        if (!config.isFollowRedirects()) {
            clientBuilder.disableRedirectHandling();
        } else { // support redirect on POST by default
            clientBuilder.setRedirectStrategy(DefaultRedirectStrategy.INSTANCE);
        }
        cookieStore = new BasicCookieStore();
        clientBuilder.setDefaultCookieStore(cookieStore);
        clientBuilder.setDefaultCookieSpecRegistry(LenientCookieSpec.registry());
        clientBuilder.useSystemProperties();
        if (config.isSslEnabled()) {
            // System.setProperty("jsse.enableSNIExtension", "false");
            String algorithm = config.getSslAlgorithm(); // could be null
            KeyStore trustStore = engine.getKeyStore(config.getSslTrustStore(), config.getSslTrustStorePassword(), config.getSslTrustStoreType());
            KeyStore keyStore = engine.getKeyStore(config.getSslKeyStore(), config.getSslKeyStorePassword(), config.getSslKeyStoreType());
            SSLContext sslContext;
            try {
                SSLContextBuilder builder = SSLContexts.custom()
                        .setProtocol(algorithm); // will default to TLS if null
                if (trustStore == null && config.isSslTrustAll()) {
                    builder = builder.loadTrustMaterial(new TrustAllStrategy());
                } else {
                    if (config.isSslTrustAll()) {
                        builder = builder.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy());
                    } else {
                        builder = builder.loadTrustMaterial(trustStore, null); // will use system / java default
                    }
                }
                if (keyStore != null) {
                    char[] keyPassword = config.getSslKeyStorePassword() == null ? null : config.getSslKeyStorePassword().toCharArray();
                    builder = builder.loadKeyMaterial(keyStore, keyPassword);
                }
                sslContext = builder.build();
                SSLConnectionSocketFactory socketFactory;
                if (keyStore != null) {
                    socketFactory = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
                } else {
                    socketFactory = new LenientSslConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
                }
                connectionManagerBuilder.setSSLSocketFactory(socketFactory);
            } catch (Exception e) {
                logger.error("ssl context init failed: {}", e.getMessage());
                throw new RuntimeException(e);
            }
        }
        connectionManagerBuilder.setDefaultConnectionConfig(ConnectionConfig.custom().setSocketTimeout(config.getReadTimeout(), TimeUnit.MILLISECONDS).setConnectTimeout(config.getConnectTimeout(), TimeUnit.MILLISECONDS).build());
        clientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setCookieSpec(LenientCookieSpec.KARATE)
                .build());
        SocketConfig.Builder socketBuilder = SocketConfig.custom().setSoTimeout(config.getConnectTimeout(), TimeUnit.MILLISECONDS);
        connectionManagerBuilder.setDefaultSocketConfig(socketBuilder.build());
        if (config.getProxyUri() != null) {
            try {
                URI proxyUri = new URIBuilder(config.getProxyUri()).build();
                clientBuilder.setProxy(new HttpHost(proxyUri.getScheme(), proxyUri.getHost(), proxyUri.getPort()));
                if (config.getProxyUsername() != null && config.getProxyPassword() != null) {
                    BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
                    credsProvider.setCredentials(
                            new AuthScope(proxyUri.getHost(), proxyUri.getPort()),
                            new UsernamePasswordCredentials(config.getProxyUsername(), config.getProxyPassword().toCharArray()));
                    clientBuilder.setDefaultCredentialsProvider(credsProvider);
                }
                if (config.getNonProxyHosts() != null) {
                    ProxySelector proxySelector = new ProxySelector() {
                        private final List<String> proxyExceptions = config.getNonProxyHosts();

                        @Override
                        public List<Proxy> select(URI uri) {
                            return Collections.singletonList(proxyExceptions.contains(uri.getHost())
                                    ? Proxy.NO_PROXY
                                    : new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyUri.getHost(), proxyUri.getPort())));
                        }

                        @Override
                        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
                            logger.info("connect failed to uri: {}", uri, ioe);
                        }
                    };
                    clientBuilder.setRoutePlanner(new SystemDefaultRoutePlanner(proxySelector));
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        clientBuilder = clientBuilder.setConnectionManager(connectionManagerBuilder.build());
        clientBuilder.addRequestInterceptorLast(this);
    }

    @Override
    public void setConfig(Config config) {
        configure(config);
    }

    @Override
    public Config getConfig() {
        return engine.getConfig();
    }

    private HttpRequest request;

    @Override
    public Response invoke(HttpRequest request) {
        this.request = request;
        ClassicRequestBuilder requestBuilder = ClassicRequestBuilder.create(request.getMethod()).setUri(request.getUrl());
        if (request.getBody() != null) {
            EntityBuilder entityBuilder = EntityBuilder.create().setBinary(request.getBody());
            List<String> transferEncoding = request.getHeaderValues(HttpConstants.HDR_TRANSFER_ENCODING);
            if (transferEncoding != null) {
                for (String te : transferEncoding) {
                    if (te == null) {
                        continue;
                    }
                    if (te.contains("chunked")) { // can be comma delimited as per spec
                        entityBuilder.chunked();
                    }
                    if (te.contains("gzip")) {
                        entityBuilder.gzipCompressed();
                    }
                }
                request.removeHeader(HttpConstants.HDR_TRANSFER_ENCODING);
            }
            requestBuilder.setEntity(entityBuilder.build());
        }
        if (request.getHeaders() != null) {
            request.getHeaders().forEach((k, vals) -> vals.forEach(v -> requestBuilder.addHeader(k, v)));
        }        
        CloseableHttpResponse httpResponse;
        byte[] bytes;
        try (CloseableHttpClient client = clientBuilder.build()) {
            httpResponse = client.execute(requestBuilder.build());
            HttpEntity responseEntity = httpResponse.getEntity();
            if (responseEntity == null || responseEntity.getContent() == null) {
                bytes = Constants.ZERO_BYTES;
            } else {
                InputStream is = responseEntity.getContent();
                bytes = FileUtils.toBytes(is);
            }
            request.setEndTime(System.currentTimeMillis());
            httpResponse.close();
        } catch (Exception e) {
            if (e instanceof ClientProtocolException && e.getCause() != null) { // better error message                
                throw new RuntimeException(e.getCause());
            } else {
                throw new RuntimeException(e);
            }
        }
        int statusCode = httpResponse.getCode();
        Map<String, List<String>> headers = toHeaders(httpResponse);
        List<Cookie> storedCookies = cookieStore.getCookies();
        Header[] requestCookieHeaders = httpResponse.getHeaders(HttpConstants.HDR_SET_COOKIE);
        // edge case where the apache client
        // auto-followed a redirect where cookies were involved
        List<String> mergedCookieValues = new ArrayList(requestCookieHeaders.length);
        Set<String> alreadyMerged = new HashSet(requestCookieHeaders.length);
        for (Header ch : requestCookieHeaders) {
            String requestCookieValue = ch.getValue();
            io.netty.handler.codec.http.cookie.Cookie c = ClientCookieDecoder.LAX.decode(requestCookieValue);            
            mergedCookieValues.add(requestCookieValue);
            alreadyMerged.add(c.name());
        }        
        for (Cookie c : storedCookies) {
            if (c.getValue() != null) {
                String name = c.getName();
                if (alreadyMerged.contains(name)) {
                    continue;
                }                
                Map<String, Object> map = new HashMap();
                map.put(Cookies.NAME, name);
                map.put(Cookies.VALUE, c.getValue());
                map.put(Cookies.DOMAIN, c.getDomain());
                if (c.getExpiryDate() != null) {
                    map.put(Cookies.MAX_AGE, c.getExpiryDate().getTime());
                }
                map.put(Cookies.SECURE, c.isSecure());
                io.netty.handler.codec.http.cookie.Cookie nettyCookie = Cookies.fromMap(map);
                String cookieValue = ServerCookieEncoder.LAX.encode(nettyCookie);
                mergedCookieValues.add(cookieValue);
            }
        }
        headers.put(HttpConstants.HDR_SET_COOKIE, mergedCookieValues);
        cookieStore.clear();
        Response response = new Response(statusCode, headers, bytes);
        httpLogger.logResponse(getConfig(), request, response);
        return response;
    }

    @Override
    public void process(org.apache.hc.core5.http.HttpRequest hr, EntityDetails entityDetails, HttpContext hc) throws HttpException, IOException {
        request.setHeaders(toHeaders(hr));
        httpLogger.logRequest(getConfig(), request);
        request.setStartTime(System.currentTimeMillis());
    }

    private static Map<String, List<String>> toHeaders(HttpMessage msg) {
        Header[] headers = msg.getHeaders();
        Map<String, List<String>> map = new LinkedHashMap(headers.length);
        for (Header outer : headers) {
            String name = outer.getName();
            Header[] inner = msg.getHeaders(name);
            List<String> list = new ArrayList(inner.length);
            for (Header h : inner) {
                list.add(h.getValue());
            }
            map.put(name, list);
        }
        return map;
    }

}
