use std::cmp::Ordering;

use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};
use rand_core::{RngCore, CryptoRng};
use serde::{Deserialize, Serialize};

use crate::{ristretto::{RistrettoPublic, RistrettoPrivate, FromRandom}, domain_separators::{DEFAULT_SUBADDRESS_INDEX, CHANGE_SUBADDRESS_INDEX, GIFT_CODE_SUBADDRESS_INDEX}};

#[derive(
    Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct PublicAddress {
    /// The user's public subaddress view key 'C'.
    view_public_key: RistrettoPublic,

    /// The user's public subaddress spend key `D`.
    spend_public_key: RistrettoPublic,
}

impl PublicAddress {
    /// Create a new public address from CryptoNote key pair (with no account
    /// service)
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public subaddress spend key `D`,
    /// `view_public_key` - The user's public subaddress view key  `C`,
    #[inline]
    pub fn new(spend_public_key: &RistrettoPublic, view_public_key: &RistrettoPublic) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
        }
    }

    /// Get the public subaddress view key.
    pub fn view_public_key(&self) -> &RistrettoPublic {
        &self.view_public_key
    }

    /// Get the public subaddress spend key.
    pub fn spend_public_key(&self) -> &RistrettoPublic {
        &self.spend_public_key
    }
}

/// Complete AccountKey, containing the pair of secret keys, which can be used
/// for spending, and optionally some fog-related info,
/// can be used for spending. This should only ever be present in client code.
#[derive(Clone)]
pub struct AccountKey {
    /// Private key 'a' used for view-key matching.
    view_private_key: RistrettoPrivate,

    /// Private key `b` used for spending.
    spend_private_key: RistrettoPrivate,
}

// Note: Hash, Ord is implemented in terms of default_subaddress() because
// we don't want comparisons to leak private key details over side-channels.
//impl Hash for AccountKey {
    //fn hash<H: Hasher>(&self, state: &mut H) {
        //self.default_subaddress().hash(state)
    //}
//}

//impl Eq for AccountKey {}

/*impl PartialEq for AccountKey {
    fn eq(&self, other: &Self) -> bool {
        self.default_subaddress().eq(&other.default_subaddress())
    }
}

impl PartialOrd for AccountKey {
    fn partial_cmp(&self, other: &AccountKey) -> Option<Ordering> {
        self.default_subaddress()
            .partial_cmp(&other.default_subaddress())
    }
}

impl Ord for AccountKey {
    fn cmp(&self, other: &AccountKey) -> Ordering {
        self.default_subaddress().cmp(&other.default_subaddress())
    }
}*/

/// Create an AccountKey from a SLIP-0010 key
/*impl From<Slip10Key> for AccountKey {
    fn from(slip10key: Slip10Key) -> Self {
        let spend_private_key = RootSpendPrivate::from(&slip10key);
        let view_private_key = RootViewPrivate::from(&slip10key);

        Self::new(spend_private_key.as_ref(), view_private_key.as_ref())
    }
}*/

impl AccountKey {
    /// A user's AccountKey, without a fog service.
    ///
    /// # Arguments
    /// * `spend_private_key` - The user's private spend key `b`.
    /// * `view_private_key` - The user's private view key `a`.
    #[inline]
    pub fn new(spend_private_key: &RistrettoPrivate, view_private_key: &RistrettoPrivate) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
        }
    }

    /// Get the view private key.
    pub fn view_private_key(&self) -> &RistrettoPrivate {
        &self.view_private_key
    }

    /// Get the spend private key.
    pub fn spend_private_key(&self) -> &RistrettoPrivate {
        &self.spend_private_key
    }

    /// Create an account key with random secret keys, and no fog service
    /// (intended for tests).
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
        )
    }

    /*/// Get the account's default subaddress.
    #[inline]
    pub fn default_subaddress(&self) -> PublicAddress {
        self.subaddress(DEFAULT_SUBADDRESS_INDEX)
    }

    /// Get the account's change subaddress.
    #[inline]
    pub fn change_subaddress(&self) -> PublicAddress {
        self.subaddress(CHANGE_SUBADDRESS_INDEX)
    }

    /// Get the account's i^th subaddress.
    pub fn subaddress(&self, index: u64) -> PublicAddress {
        let (view_public, spend_public) = (
            &RootViewPrivate::from(self.view_private_key),
            &RootSpendPublic::from(*self.spend_public_key()),
        )
            .subaddress(index);

        PublicAddress {
            view_public_key: view_public.inner(),
            spend_public_key: spend_public.inner(),
            fog_report_url: "".to_string(),
            fog_report_id: "".to_string(),
            fog_authority_sig: Vec::default(),
        }
    }

    /// The public spend key for the default subaddress.
    pub fn default_subaddress_spend_public(&self) -> RistrettoPublic {
        self.subaddress_spend_public(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The public spend key for the change subaddress.
    pub fn change_subaddress_spend_public(&self) -> RistrettoPublic {
        self.subaddress_spend_public(CHANGE_SUBADDRESS_INDEX)
    }

    /// The public spend key for the gift code subaddress.
    pub fn gift_code_subaddress_spend_public(&self) -> RistrettoPublic {
        self.subaddress_spend_public(GIFT_CODE_SUBADDRESS_INDEX)
    }

    /// The private spend key for the i^th subaddress.
    pub fn subaddress_spend_public(&self, index: u64) -> RistrettoPublic {
        let (_view_public, spend_public) = (
            &RootViewPrivate::from(self.view_private_key),
            &RootSpendPublic::from(*self.spend_public_key()),
        )
            .subaddress(index);

        spend_public.inner()
    }

    /// The private view key for the default subaddress.
    pub fn default_subaddress_view_public(&self) -> RistrettoPublic {
        self.subaddress_view_public(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The private view key for the change subaddress.
    pub fn change_subaddress_view_public(&self) -> RistrettoPublic {
        self.subaddress_view_public(CHANGE_SUBADDRESS_INDEX)
    }

    /// The private view key for the change subaddress.
    pub fn gift_code_subaddress_view_public(&self) -> RistrettoPublic {
        self.subaddress_view_public(GIFT_CODE_SUBADDRESS_INDEX)
    }

    /// The private view key for the i^th subaddress.
    pub fn subaddress_view_public(&self, index: u64) -> RistrettoPublic {
        let a: &Scalar = self.view_private_key.as_ref();
        let b: RistrettoPoint = a * self.subaddress_spend_public(index).as_ref();

        RistrettoPublic::from(b)
    }*/
}