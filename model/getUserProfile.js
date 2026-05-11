const supabase = require("../dbConnection.js");
const { decrypt } = require("../services/encryptionService");

async function decryptSensitiveFields(profile) {
	if (!profile) {
		return profile;
	}

	// Only attempt decryption when the value looks like the legacy per-column
	// JSON-encoded encrypted format. Plain text and null values are returned as-is.
	const tryDecryptField = async (value) => {
		if (!value) return value;
		let parsed;
		try {
			parsed = JSON.parse(value);
		} catch (_) {
			return value; // plain text — return unchanged
		}
		if (!parsed || !parsed.encrypted || !parsed.iv || !parsed.authTag) return value;
		return await decrypt(parsed.encrypted, parsed.iv, parsed.authTag);
	};

	return {
		...profile,
		contact_number: await tryDecryptField(profile.contact_number),
		address: await tryDecryptField(profile.address),
	};
}

async function getUserProfile(lookup = {}) {
	try {
		const query = supabase
			.from("users")
			.select(
				"user_id,name,first_name,last_name,email,contact_number,mfa_enabled,address,image_id,registration_date,last_login,account_status,user_roles!left(role_name),profile_encrypted,profile_encryption_iv,profile_encryption_auth_tag,profile_encryption_key_version"
			);

		if (lookup.userId != null) {
			query.eq("user_id", lookup.userId);
		} else if (lookup.email) {
			query.eq("email", lookup.email);
		} else {
			throw new Error("A userId or email lookup is required");
		}

		const { data, error } = await query.maybeSingle();
		if (error) {
			throw error;
		}

		if (!data) {
			return null;
		}

		const profile = await decryptSensitiveFields(data);

		if (profile.image_id != null) {
			profile.image_url = await getImageUrl(profile.image_id);
		} else {
			profile.image_url = null;
		}

		return profile;
	} catch (error) {
		throw error;
	}
}

async function getImageUrl(image_id) {
	try {
		if (image_id == null) return "";
		let { data } = await supabase
			.from("images")
			.select("*")
			.eq("id", image_id);
		if (data[0] != null) {
			return await resolveImageUrl(data[0].file_name);
		}
		return data;
	} catch (error) {
		console.log(error);
		throw error;
	}
}

async function resolveImageUrl(file_name) {
	if (!file_name) return null;

	// Signed URL works for both public and private buckets.
	const { data: signedData, error: signedError } = await supabase
		.storage
		.from("images")
		.createSignedUrl(file_name, 60 * 60 * 24);

	if (!signedError && signedData?.signedUrl) {
		return signedData.signedUrl;
	}

	// Fallback to public URL if signing fails for any reason.
	const { data: publicData } = supabase
		.storage
		.from("images")
		.getPublicUrl(file_name);

	return publicData?.publicUrl || null;
}

module.exports = getUserProfile;
