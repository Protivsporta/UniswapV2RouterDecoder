//! Uniswap V2 router calldata parser.
//!
//! Decodes all nine canonical UniV2 swap variants from raw transaction calldata.

use alloy::{
    primitives::{Address, U256},
    sol,
    sol_types::SolCall,
};
use smallvec::SmallVec;
use thiserror::Error;

sol! {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] path,
        address to,
        uint256 deadline
    ) external returns (uint256[] amounts);

    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] path,
        address to,
        uint256 deadline
    ) external returns (uint256[] amounts);

    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] path,
        address to,
        uint256 deadline
    ) external returns (uint256[] amounts);

    function swapTokensForExactETH(
        uint256 amountOut,
        uint256 amountInMax,
        address[] path,
        address to,
        uint256 deadline
    ) external returns (uint256[] amounts);

    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] path,
        address to,
        uint256 deadline
    ) external returns (uint256[] amounts);

    function swapETHForExactTokens(
        uint256 amountOut,
        address[] path,
        address to,
        uint256 deadline
    ) external returns (uint256[] amounts);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] path,
        address to,
        uint256 deadline
    ) external;

    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin,
        address[] path,
        address to,
        uint256 deadline
    ) external;

    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] path,
        address to,
        uint256 deadline
    ) external;
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("calldata too short: need ≥4 bytes, got {0}")]
    TooShort(usize),

    #[error("unknown selector {0:#010x} — not a recognised UniV2 swap")]
    UnknownSelector(u32),

    #[error("ABI decode failed: {0}")]
    AbiDecode(#[from] alloy::sol_types::Error),

    #[error("path must contain ≥2 tokens, got {0}")]
    PathTooShort(usize),
}

/// Sorted token pair identifying a UniV2 pool.
///
/// Sorted ascending to match the factory's CREATE2 derivation — `(A,B)` and
/// `(B,A)` resolve to the same pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolPair {
    pub token0: Address, // always the lower address
    pub token1: Address,
}

impl PoolPair {
    #[inline]
    pub fn new(a: Address, b: Address) -> Self {
        if a < b { Self { token0: a, token1: b } } else { Self { token0: b, token1: a } }
    }
}

/// Pinned side of a swap. ETH variants carry `msg.value` directly so no
/// separate `eth_value` field is needed on the outer struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapAmounts {
    ExactIn    { amount_in: U256,  amount_out_min: U256 },
    ExactInEth { eth_in: U256,     amount_out_min: U256 }, // eth_in == msg.value
    ExactOut   { amount_out: U256, amount_in_max: U256  },
    ExactOutEth{ amount_out: U256, eth_in_max: U256     }, // eth_in_max == msg.value
}

/// Fully decoded UniV2 swap call.
///
/// `path` is stack-allocated for ≤4 hops (the common case) via `SmallVec`.
/// Pool pairs are derived lazily — see [`ParsedV2Swap::pairs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedV2Swap {
    pub method:   &'static str,
    pub path:     SmallVec<[Address; 4]>,
    pub amounts:  SwapAmounts,
    pub deadline: u64,
}

impl ParsedV2Swap {
    /// Consecutive sorted pool hops: `[A,B,C]` → `PoolPair(A,B), PoolPair(B,C)`.
    #[inline]
    pub fn pairs(&self) -> impl Iterator<Item = PoolPair> + '_ {
        self.path.windows(2).map(|w| PoolPair::new(w[0], w[1]))
    }
}

/// Decode a single UniV2 swap call from raw calldata.
///
/// `eth_value` is `msg.value` from the transaction envelope — forwarded into
/// `ExactInEth`/`ExactOutEth` for the two ETH-in variants, ignored otherwise.
pub fn parse_v2_swap(calldata: &[u8], eth_value: U256) -> Result<ParsedV2Swap, ParseError> {
    if calldata.len() < 4 {
        return Err(ParseError::TooShort(calldata.len()));
    }

    // The compiler lowers this to a jump table — O(1) dispatch over nine variants.
    // SAFETY: length checked above
    let sel: [u8; 4] = calldata[..4].try_into().unwrap();

    match sel {
        swapExactTokensForTokensCall::SELECTOR => {
            let c = swapExactTokensForTokensCall::abi_decode(calldata, false)?;
            build(
                "swapExactTokensForTokens",
                c.path,
                SwapAmounts::ExactIn { amount_in: c.amountIn, amount_out_min: c.amountOutMin },
                c.deadline,
            )
        }

        swapExactETHForTokensCall::SELECTOR => {
            let c = swapExactETHForTokensCall::abi_decode(calldata, false)?;
            build(
                "swapExactETHForTokens",
                c.path,
                SwapAmounts::ExactInEth { eth_in: eth_value, amount_out_min: c.amountOutMin },
                c.deadline,
            )
        }

        swapExactTokensForETHCall::SELECTOR => {
            let c = swapExactTokensForETHCall::abi_decode(calldata, false)?;
            build(
                "swapExactTokensForETH",
                c.path,
                SwapAmounts::ExactIn { amount_in: c.amountIn, amount_out_min: c.amountOutMin },
                c.deadline,
            )
        }

        swapTokensForExactTokensCall::SELECTOR => {
            let c = swapTokensForExactTokensCall::abi_decode(calldata, false)?;
            build(
                "swapTokensForExactTokens",
                c.path,
                SwapAmounts::ExactOut { amount_out: c.amountOut, amount_in_max: c.amountInMax },
                c.deadline,
            )
        }

        swapTokensForExactETHCall::SELECTOR => {
            let c = swapTokensForExactETHCall::abi_decode(calldata, false)?;
            build(
                "swapTokensForExactETH",
                c.path,
                SwapAmounts::ExactOut { amount_out: c.amountOut, amount_in_max: c.amountInMax },
                c.deadline,
            )
        }

        swapETHForExactTokensCall::SELECTOR => {
            let c = swapETHForExactTokensCall::abi_decode(calldata, false)?;
            build(
                "swapETHForExactTokens",
                c.path,
                SwapAmounts::ExactOutEth { amount_out: c.amountOut, eth_in_max: eth_value },
                c.deadline,
            )
        }

        swapExactTokensForTokensSupportingFeeOnTransferTokensCall::SELECTOR => {
            let c = swapExactTokensForTokensSupportingFeeOnTransferTokensCall::abi_decode(
                calldata, false,
            )?;
            build(
                "swapExactTokensForTokensSupportingFeeOnTransferTokens",
                c.path,
                SwapAmounts::ExactIn { amount_in: c.amountIn, amount_out_min: c.amountOutMin },
                c.deadline,
            )
        }

        swapExactETHForTokensSupportingFeeOnTransferTokensCall::SELECTOR => {
            let c = swapExactETHForTokensSupportingFeeOnTransferTokensCall::abi_decode(
                calldata, false,
            )?;
            build(
                "swapExactETHForTokensSupportingFeeOnTransferTokens",
                c.path,
                SwapAmounts::ExactInEth { eth_in: eth_value, amount_out_min: c.amountOutMin },
                c.deadline,
            )
        }

        swapExactTokensForETHSupportingFeeOnTransferTokensCall::SELECTOR => {
            let c = swapExactTokensForETHSupportingFeeOnTransferTokensCall::abi_decode(
                calldata, false,
            )?;
            build(
                "swapExactTokensForETHSupportingFeeOnTransferTokens",
                c.path,
                SwapAmounts::ExactIn { amount_in: c.amountIn, amount_out_min: c.amountOutMin },
                c.deadline,
            )
        }

        _ => Err(ParseError::UnknownSelector(u32::from_be_bytes(sel))),
    }
}

/// Decode a batch into `out`, silently skipping unparseable entries.
///
/// Caller holds `out` across blocks — capacity amortises to zero after warmup.
pub fn parse_v2_swaps<'a>(
    txs: impl IntoIterator<Item = (&'a [u8], U256)>,
    out: &mut Vec<ParsedV2Swap>,
) {
    out.extend(txs.into_iter().filter_map(|(data, value)| parse_v2_swap(data, value).ok()));
}

#[inline]
fn build(
    method: &'static str,
    path: Vec<Address>,
    amounts: SwapAmounts,
    deadline: U256,
) -> Result<ParsedV2Swap, ParseError> {
    if path.len() < 2 {
        return Err(ParseError::PathTooShort(path.len()));
    }
    Ok(ParsedV2Swap {
        method,
        path: SmallVec::from_vec(path),
        amounts,
        deadline: deadline.to::<u64>(),
    })
}
