package com.serviceplus.UserManagement.profile.service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;

@Service
public class BucketService {

	@Autowired
	private ProxyManager<byte[]> proxyManager;

	private static final String REQUEST_BUCKET_PREFIX = "modifyProfileEmailRequestBucket:";
	private static final String VERIFY_BUCKET_PREFIX = "modifyProfileEmailVerifyBucket:";

	@Value("${modify.profile.email.sms.request.limit}")
	private Integer requestLimit;
	

	@Value("${modify.profile.email.sms.session.validity.min}")
	private Integer sessionValidityMin;

	@Value("${modify.profile.email.sms.otp.attemps}")
	private Integer totalOtpAttemps;
	
	@Value("${modify.profile.email.sms.otp.attemps.block.time}")
	private Integer otpAttempsBlockTime;
	
	private byte[] key(String rawKey) {
		return rawKey.getBytes(StandardCharsets.UTF_8);
	}

	public Bucket getOtpRequestBucket(Long userId) {
		byte[] key = key(REQUEST_BUCKET_PREFIX + userId);
		Supplier<BucketConfiguration> config = () -> BucketConfiguration.builder()
				.addLimit(Bandwidth.builder().capacity(requestLimit).refillIntervally(requestLimit, Duration.ofMinutes(sessionValidityMin)).build()).build();
		return proxyManager.builder().build(key, config);
	}

	public Bucket getOtpVerifyBucket(Long userId) {
		byte[] key = key(VERIFY_BUCKET_PREFIX + userId);
		Supplier<BucketConfiguration> config = () -> BucketConfiguration.builder()
				.addLimit(Bandwidth.builder().capacity(totalOtpAttemps).refillIntervally(totalOtpAttemps, Duration.ofMinutes(otpAttempsBlockTime)).build()).build();
		return proxyManager.builder().build(key, config);
	}

	public void resetVerifyBucket(Long userId) {
		proxyManager.removeProxy(key(VERIFY_BUCKET_PREFIX + userId));
	}
	
    private static final String TRACKING_REQUEST_PREFIX = "trackingOtpRequestBucket:";
    private static final String TRACKING_VERIFY_PREFIX = "trackingOtpVerifyBucket:";

    public Bucket getTrackingRequestBucket(String identityKey) {
        return trackingBucket(TRACKING_REQUEST_PREFIX + identityKey, requestLimit, sessionValidityMin);
    }

    public Bucket getTrackingVerifyBucket(String challengeId) {
        return trackingBucket(TRACKING_VERIFY_PREFIX + challengeId, totalOtpAttemps, otpAttempsBlockTime);
    }

    private Bucket trackingBucket(String name, int capacity, int minutes) {
        Supplier<BucketConfiguration> config = () -> BucketConfiguration.builder()
                .addLimit(Bandwidth.builder().capacity(capacity)
                        .refillIntervally(capacity, Duration.ofMinutes(minutes)).build())
                .build();
        return proxyManager.builder().build(key(name), config);
    }
}
