package com.serviceplus.UserManagement.profile.service;

import static com.serviceplus.UserManagement.util.SnowflakeIdGenerator.createUniqueId;

import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.serviceplus.UserManagement.Dto.NotificationRequestDTO;
import com.serviceplus.UserManagement.Dto.NotificationResponseDTO;
import com.serviceplus.UserManagement.Entity.UserProfile;
import com.serviceplus.UserManagement.Entity.UserSessionObject;
import com.serviceplus.UserManagement.ExceptionHandler.SPRuntimeError;
import com.serviceplus.UserManagement.Kafka.NotificationKafkaService;
import com.serviceplus.UserManagement.Repository.UserProfileRepository;
import com.serviceplus.UserManagement.Service.TenantConfiguration;
import com.serviceplus.UserManagement.feign.EsbFeignClient;
import com.serviceplus.UserManagement.profile.dto.ModifyEmailDTO;
import com.serviceplus.UserManagement.profile.dto.ModifyProfileOtpDTO;
import com.serviceplus.UserManagement.profile.dto.UserModifyProfileDTO;
import com.serviceplus.UserManagement.util.Utility;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;

@Service
public class ModifyProfileService {
	@Autowired
	private UserProfileRepository profileRepository;
	@Autowired
	private ModifyProfileRedisService redisService;
	@Autowired
	private NotificationKafkaService kafkaService;

	@Autowired
	private BucketService bucketService;
	
	@Autowired
	private TenantConfiguration tenantConfiguration;
	
	@Autowired
	private EsbFeignClient esbFeign;

	private static final Logger LOG = LogManager.getLogger("ModifyProfile");
	private static final SecureRandom random = new SecureRandom();

	private static final Tika TIKA = new Tika();

	@Value("${modify.profile.email.sms.otp.validity.min}")
	private Integer validityMin;

	@Value("${modify.profile.email.otp.subject}")
	private String MODIFY_PROFILE_EMAIL_SUBJECT;

	@Value("${modify.profile.email.otp.content}")
	private String MODIFY_PROFILE_EMAIL_CONTENT;

	@Value("${modify.profile.image.max.limit}")
	private int maxImageSizeInMB;

	@Value("${modify.profile.image.extensions}")
	private String allowedExtensions;

	public ResponseEntity<?> requestEmailOtp(HttpServletRequest request, UserSessionObject user, Long userID, String emailId) {
		try {
			UserProfile userProfile = profileRepository.findByUserId(userID);
			if (userProfile == null) {
				throw new SPRuntimeError("Invalid User", HttpStatus.BAD_REQUEST);
			}

			if (!Utility.isValidEmail(emailId)) {
				throw new SPRuntimeError("Please enter a valid email address.", HttpStatus.BAD_REQUEST);
			}

			if (userProfile.getEmailId() != null && emailId.equals(userProfile.getEmailId())) {
				return ResponseEntity.badRequest()
						.body(Map.of("message","New email address must be different from the current email address."));
			}


			Bucket requestBucket = bucketService.getOtpRequestBucket(userID);
			
			ConsumptionProbe probe = requestBucket.tryConsumeAndReturnRemaining(1);

			if (!probe.isConsumed()) {
				long waitMinutes = Math.max(1, (probe.getNanosToWaitForRefill() / 1_000_000_000L) / 60);
				throw new SPRuntimeError(
						"You reached the maximum OTP request limit. Please retry after " + waitMinutes + " minute(s).",
						HttpStatus.BAD_REQUEST);
			}

			String emailOtp = String.format("%06d", 100000 + random.nextInt(900000));
			LOG.info("Generated Email OTP: {}", emailOtp);
			// overwrites any previous OTP, TTL = 15 min
			redisService.saveOtp(userID, emailId, emailOtp);

			// fresh OTP => fresh verify-attempt count
			bucketService.resetVerifyBucket(userID);

			String emailContent = MessageFormat.format(MODIFY_PROFILE_EMAIL_CONTENT, emailOtp, validityMin);
			NotificationRequestDTO requestDto = new NotificationRequestDTO();
			Map<String, Object> recipient = new HashMap<>();
			Map<String, Object> configuration = new HashMap<>();
			Map<String, Object> payload = new HashMap<>();
			String keys="MAIL";
	    	
			configuration =tenantConfiguration.fetchConfig(request, user.getTenantId(), keys);

			@SuppressWarnings("unchecked")
			Map<String, Object> data =
			        (Map<String, Object>) configuration.get("data");

			@SuppressWarnings("unchecked")
			Map<String, Object> mailConfiguration =
			        (Map<String, Object>) data.get("MAIL");

			String provider = (String) mailConfiguration.get("provider");

			requestDto.setTenantId(userProfile.getTenantId());
			requestDto.setChannel("EMAIL");
			requestDto.setProvider(provider);

			recipient.put("to", List.of(emailId));
			requestDto.setRecipient(recipient);

			payload.put("subject", MODIFY_PROFILE_EMAIL_SUBJECT);
			payload.put("body", emailContent);
			requestDto.setPayload(payload);

			requestDto.setConfiguration(mailConfiguration);
			requestDto.setCorrelationId(createUniqueId());
			NotificationResponseDTO response =esbFeign.send(requestDto);

			if (!response.isSuccess()) {
			    throw new SPRuntimeError("Unable to send OTP email.",HttpStatus.INTERNAL_SERVER_ERROR);
			}

			return ResponseEntity.ok(Map.of("message", "OTP has been sent successfully to your email."));
		} catch (Exception e) {
			if (e instanceof SPRuntimeError) {
				throw e;
			} else {
				LOG.error("ModifyProfile-Error : {}", e);
				throw new SPRuntimeError("Something went wrong", HttpStatus.INTERNAL_SERVER_ERROR);
			}
		}
	}

	public ResponseEntity<?> verifyEmailOtp(Long userID, ModifyEmailDTO modifyEmailDTO) {
		try {
			UserProfile userProfile = profileRepository.findByUserId(userID);
			if (userProfile == null) {
				throw new SPRuntimeError("Invalid User", HttpStatus.BAD_REQUEST);
			}

			ModifyProfileOtpDTO otpDto = redisService.getOtp(userID);
			if (otpDto == null) {
				throw new SPRuntimeError("OTP expired. Please request a new OTP.", HttpStatus.BAD_REQUEST);
			}

			String requestOtp = modifyEmailDTO.getOtp();

			if (otpDto.getOtp().equals(requestOtp)) {
				userProfile.setEmailId(otpDto.getEmail());
				profileRepository.save(userProfile);

				redisService.deleteOtp(userID);
				bucketService.resetVerifyBucket(userID);

				return ResponseEntity.ok(Map.of("message", "Email updated successfully."));
			}

			Bucket verifyBucket = bucketService.getOtpVerifyBucket(userID);
			ConsumptionProbe probe = verifyBucket.tryConsumeAndReturnRemaining(1);
			long remaining = probe.getRemainingTokens();

			if (remaining > 0) {
				return ResponseEntity.badRequest().body(Map.of("message","Wrong OTP. " + remaining + " attempt(s) remaining."));
			}

			// 3rd wrong attempt just consumed the last token
			redisService.deleteOtp(userID);
			bucketService.resetVerifyBucket(userID);
			throw new SPRuntimeError("Maximum OTP verification attempts exceeded. Please request a new OTP.",
					HttpStatus.BAD_REQUEST);

		} catch (Exception e) {
			if (e instanceof SPRuntimeError) {
				throw e;
			} else {
				LOG.error("ModifyProfile-Error : {}", e);
				throw new SPRuntimeError("Something went wrong", HttpStatus.INTERNAL_SERVER_ERROR);
			}
		}
	}

	public ResponseEntity<?> saveProfile(Long userID, UserModifyProfileDTO profileDTO) {
		try {
			UserProfile userProfile = profileRepository.findByUserId(userID);
			if (userProfile == null) {
				throw new SPRuntimeError("Invalid User", HttpStatus.BAD_REQUEST);
			}

			String profilePic = profileDTO.getProfilePic();
			if (profilePic != null) {
				byte[] decoded;
				try {
					decoded = Base64.getDecoder().decode(profilePic);
				} catch (Exception e) {
					throw new SPRuntimeError("Invalid image Base64.", HttpStatus.BAD_REQUEST);
				}
				long maxSize = maxImageSizeInMB * 1024L * 1024L;
				if (decoded.length > maxSize) {
					throw new SPRuntimeError("Maximum " + maxImageSizeInMB + " MB image is allowed.",
							HttpStatus.BAD_REQUEST);
				}

				String detectedType = TIKA.detect(decoded);

				Set<String> allowedMimeTypes = Arrays.stream(allowedExtensions.split(",")).map(String::trim)
						.map(ext -> {
							switch (ext.toLowerCase()) {
							case ".jpg":
							case ".jpeg":
								return "image/jpeg";
							case ".png":
								return "image/png";
							default:
								return "";
							}
						}).filter(s -> !s.isEmpty()).collect(Collectors.toSet());

				if (!allowedMimeTypes.contains(detectedType)) {
					throw new SPRuntimeError("Only " + allowedExtensions + " files are allowed.",
							HttpStatus.BAD_REQUEST);
				}
				userProfile.setProfilePic(decoded);
			}

			userProfile.setUserName(profileDTO.getUserName());
			userProfile.setMiddleName(profileDTO.getMiddleName());
			userProfile.setLastName(profileDTO.getLastName());
			userProfile.setDob(profileDTO.getDob());
			userProfile.setAddress(profileDTO.getAddress());
			userProfile.setPostalCode(profileDTO.getPostalCode());
			userProfile.setuDate(new Date());

			profileRepository.save(userProfile);
			LOG.info("ModifyProfile-Update with userId {}", userID);

			return ResponseEntity.ok(Map.of("message", "Profile updated successfully."));

		} catch (Exception e) {
			if (e instanceof SPRuntimeError) {
				throw e;
			}

			LOG.error("ModifyProfile-Error : {}", e);
			throw new SPRuntimeError("Something went wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

}
