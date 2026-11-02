package com.serviceplus.UserManagement.profile.service;

import java.util.Map;
import java.util.Collections;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.serviceplus.UserManagement.ExceptionHandler.SPRuntimeError;
import com.serviceplus.UserManagement.profile.dto.ModifyProfileOtpDTO;
import com.fasterxml.jackson.core.type.TypeReference;

@Service
public class ModifyProfileRedisService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${modify.profile.email.sms.otp.validity.min}")
    private Integer otpValidityMin;

    @Value("${tracking.otp.validity-minutes:5}")
    private int trackingValidityMinutes;

    private static final String KEY_PREFIX = "modifyProfileEmailOtp:";

    public void saveOtp(Long userId, String email, String otp) {
        try {
            ModifyProfileOtpDTO dto = new ModifyProfileOtpDTO(otp, email);
            String json = objectMapper.writeValueAsString(dto);
            redisTemplate.opsForValue().set(KEY_PREFIX + userId, json, otpValidityMin, TimeUnit.MINUTES);
        } catch (Exception e) {
            e.printStackTrace();
            throw new SPRuntimeError("Something went wrong", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ModifyProfileOtpDTO getOtp(Long userId) {
        try {
            String json = redisTemplate.opsForValue().get(KEY_PREFIX + userId);
            return json != null ? objectMapper.readValue(json, ModifyProfileOtpDTO.class) : null;
        } catch (Exception e) {
            e.printStackTrace();
            throw new SPRuntimeError("Something went wrong", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void deleteOtp(Long userId) {
        redisTemplate.delete(KEY_PREFIX + userId);
    }
    

    private static final String TRACKING_OTP_PREFIX = "tracking:otp:";

    /**
     * Atomically consumes a verified tracking challenge.
     * Nonce and stored HMAC must still match the challenge that was validated.
     * Two concurrent verify calls cannot both consume the same challenge.
     */
    private static final RedisScript<Long> CONSUME_TRACKING_OTP_SCRIPT = new DefaultRedisScript<>(
            "local raw = redis.call('GET', KEYS[1])\n"
            + "if not raw then return 0 end\n"
            + "local ok, challenge = pcall(cjson.decode, raw)\n"
            + "if not ok or type(challenge) ~= 'table' then return 0 end\n"
            + "if challenge.purpose == 'PUBLIC_TRACKING' and challenge.nonce == ARGV[1] and challenge.otpHash == ARGV[2] then\n"
            + "  return redis.call('DEL', KEYS[1])\n"
            + "end\n"
            + "return 0", Long.class);



    public String saveTrackingOtp(Map<String, Object> otpData) {
        if (trackingValidityMinutes < 1 || trackingValidityMinutes > 15) {
            throw new IllegalStateException("Invalid tracking OTP validity");
        }
        try {
            String challengeId = UUID.randomUUID().toString();
            String json = objectMapper.writeValueAsString(otpData);
            redisTemplate.opsForValue().set(
                    TRACKING_OTP_PREFIX + challengeId, json, trackingValidityMinutes, TimeUnit.MINUTES);
            return challengeId;
        } catch (Exception e) {
            throw new SPRuntimeError("Unable to save tracking OTP", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public Map<String, Object> getTrackingOtp(String challengeId) {
        try {
            if (challengeId == null || challengeId.isBlank()) {
                return null;
            }
            String json = redisTemplate.opsForValue().get(TRACKING_OTP_PREFIX + challengeId);
            return json != null
                    ? objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {})
                    : null;
        } catch (Exception e) {
            throw new SPRuntimeError("Unable to retrieve tracking OTP", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public boolean consumeTrackingOtp(String challengeId, String nonce, String expectedHash) {
        if (challengeId == null || challengeId.isBlank()
                || nonce == null || nonce.isBlank()
                || expectedHash == null || expectedHash.isBlank()) {
            return false;
        }
        try {
            Long consumed = redisTemplate.execute(CONSUME_TRACKING_OTP_SCRIPT,
                    Collections.singletonList(TRACKING_OTP_PREFIX + challengeId),
                    nonce, expectedHash);
            return Long.valueOf(1L).equals(consumed);
        } catch (Exception e) {
            throw new SPRuntimeError("Unable to consume tracking OTP", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void deleteTrackingOtp(String challengeId) {
        if (challengeId == null || challengeId.isBlank()) {
            return;
        }
        redisTemplate.delete(TRACKING_OTP_PREFIX + challengeId);
    }
}
