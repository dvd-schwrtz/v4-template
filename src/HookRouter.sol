// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {BaseHook} from "v4-periphery/BaseHook.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "forge-std/console.sol";

/// @title Hook Router for Uniswap v4
/// @notice Let's a single hook route permissioned calls to other "pass through" hooks, supporting infinite hooks in a single pool
/// Aimed at developers who lack the ability to attract liquidity or connect with Quoters for discovery,
/// they could attach hooks to a Hook Router pool instead. Security issues are a bigger issue and must be managed by
/// the pool owner via the allow and block lists for external hooks that wish to use the Hook Router. Any hook may be
/// called by the HookRouter contract, creating a permissionless extension of hooks on top of the single hook design in v4.
contract HookRouter is BaseHook, Ownable {
    error InvalidHookRouterResponse();
    error FailedHookRouterCall();

    /// @notice the contract owner controls if there is an allow list and/or a block list of hooks to call
    bool public hasHookAllowList;
    bool public hasHookBlockList;

    mapping(address => bool) public hookAllowList;
    mapping(address => bool) public hookBlockList;

    /// @notice Creates a new HookRouter contract
    /// @param _poolManager The pool manager to be used by the HookRouter
    constructor(IPoolManager _poolManager) Ownable(msg.sender) BaseHook(_poolManager) {}

    /// @notice Retrieves the permissions for different hook types
    /// @return Permissions struct detailing allowed operations
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: true,
            beforeAddLiquidity: true,
            beforeRemoveLiquidity: true,
            afterAddLiquidity: true,
            afterRemoveLiquidity: true,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: true,
            afterDonate: true
        });
    }

    /// @dev Extracts a pass-through hook address and the remaining data from hookData for routing.
    /// @param _hookData The encoded hook calldata containing an address followed by arbitrary bytes.
    /// @param _flag The address bit to check if there is a method defined in the pass through hook
    /// @return passThroughHook A BaseHook instance created from the extracted address within hookData.
    function _getPassThroughHook(bytes memory _hookData, uint256 _flag)
        private
        pure
        returns (BaseHook passThroughHook)
    {
        address extractedAddress;
        assembly {
            extractedAddress := mload(add(_hookData, 20))
        }
        passThroughHook = BaseHook(extractedAddress);
        if (!hasRoutingPermission(passThroughHook, _flag)) {
            passThroughHook = BaseHook(address(0));
        }
    }

    /// @dev Calls the designated pass-through hook with provided data
    /// @param _passThroughHook A BaseHook instance to call
    /// @param _data The data to be passed to the hook instance
    function _callPassThroughHook(BaseHook _passThroughHook, bytes memory _data) private {
        bytes4 expectedSelector;
        assembly {
            expectedSelector := mload(add(_data, 0x20))
        }
        if (hasHookAllowList) {
            require(hookAllowList[address(_passThroughHook)], "not in allow list");
        }
        if (hasHookBlockList) {
            require(!hookBlockList[address(_passThroughHook)], "address in block list");
        }
        (bool success, bytes memory result) = address(_passThroughHook).call(_data);
        if (!success) _revert(result);

        bytes4 selector = abi.decode(result, (bytes4));
        if (selector != expectedSelector) {
            revert InvalidHookRouterResponse();
        }
    }

    /// @dev checks if the hook to route to has the function necessary
    /// @param _passThroughHook A BaseHook instance to check
    /// @param _flag The bit of the address to check against
    /// @return a boolean saying if the method exists on the pass through hook
    function hasRoutingPermission(BaseHook _passThroughHook, uint256 _flag) internal pure returns (bool) {
        return uint256(uint160(address(_passThroughHook))) & _flag != 0;
    }

    function _handleRouting(bytes calldata _hookData, uint256 _flag, bytes4 _selector, bytes memory _data)
        private
        returns (bytes4)
    {
        BaseHook passThroughHook = _getPassThroughHook(_hookData, _flag);
        if (address(passThroughHook) == address(0)) {
            return _selector;
        }
        _callPassThroughHook(passThroughHook, _data);
        return _selector;
    }

    /// @notice Hook called before pool initialization
    /// @param sender The original sender of the initialization call
    /// @param key The pool key identifying the pool
    /// @param sqrtPriceX96 The initial sqrt price of the pool
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the beforeInitialize hook
    function beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, bytes calldata hookData)
        external
        override
        returns (bytes4)
    {
        return _handleRouting(
            hookData,
            Hooks.BEFORE_INITIALIZE_FLAG,
            BaseHook.beforeInitialize.selector,
            abi.encodeWithSelector(
                BaseHook.beforeInitialize.selector, sender, key, sqrtPriceX96, removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called after pool initialization
    /// @param sender The original sender of the initialization call
    /// @param key The pool key identifying the pool
    /// @param sqrtPriceX96 The initial sqrt price of the pool after initialization
    /// @param tick The initial tick of the pool
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the afterInitialize hook
    function afterInitialize(
        address sender,
        PoolKey calldata key,
        uint160 sqrtPriceX96,
        int24 tick,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.AFTER_INITIALIZE_FLAG,
            BaseHook.afterInitialize.selector,
            abi.encodeWithSelector(
                BaseHook.afterInitialize.selector, sender, key, sqrtPriceX96, tick, removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called before a swap
    /// @param sender The original sender of the swap call
    /// @param key The pool key identifying the pool
    /// @param swapParams The params for the swap
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the afterSwap hook
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata swapParams,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.BEFORE_SWAP_FLAG,
            BaseHook.beforeSwap.selector,
            abi.encodeWithSelector(BaseHook.beforeSwap.selector, sender, key, swapParams, removeFirst20Bytes(hookData))
        );
    }

    /// @notice Hook called after a swap
    /// @param sender The original sender of the swap call
    /// @param key The pool key identifying the pool
    /// @param swapParams The params for the swap
    /// @param balanceDelta The token balance delta created by the swap
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the afterSwap hook
    function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata swapParams,
        BalanceDelta balanceDelta,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.AFTER_SWAP_FLAG,
            BaseHook.afterSwap.selector,
            abi.encodeWithSelector(
                BaseHook.afterSwap.selector, sender, key, swapParams, balanceDelta, removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called before adding liquidity
    /// @param sender The original sender of the before add liquidity call
    /// @param key The pool key identifying the pool
    /// @param modifyLiquidityParams The params for the liquidity modification
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the beforeAddLiquidity hook
    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata modifyLiquidityParams,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.BEFORE_ADD_LIQUIDITY_FLAG,
            BaseHook.beforeAddLiquidity.selector,
            abi.encodeWithSelector(
                BaseHook.beforeAddLiquidity.selector, sender, key, modifyLiquidityParams, removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called after adding liquidity
    /// @param sender The original sender of the add liquidity call
    /// @param key The pool key identifying the pool
    /// @param modifyLiquidityParams The params for the liquidity modification
    /// @param balanceDelta The token balance delta created by the liquidity modification
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the afterAddLiquidity hook
    function afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata modifyLiquidityParams,
        BalanceDelta balanceDelta,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.AFTER_ADD_LIQUIDITY_FLAG,
            BaseHook.afterAddLiquidity.selector,
            abi.encodeWithSelector(
                BaseHook.afterAddLiquidity.selector,
                sender,
                key,
                modifyLiquidityParams,
                balanceDelta,
                removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called before removing liquidity
    /// @param sender The original sender of the before remove liquidity call
    /// @param key The pool key identifying the pool
    /// @param modifyLiquidityParams The params for the liquidity modification
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the beforeRemoveLiquidity hook
    function beforeRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata modifyLiquidityParams,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG,
            BaseHook.beforeRemoveLiquidity.selector,
            abi.encodeWithSelector(
                BaseHook.beforeRemoveLiquidity.selector,
                sender,
                key,
                modifyLiquidityParams,
                removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called after removing liquidity
    /// @param sender The original sender of the remove liquidity call
    /// @param key The pool key identifying the pool
    /// @param modifyLiquidityParams The params for the liquidity modification
    /// @param balanceDelta The token balance delta created by the liquidity modification
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the afterRemoveLiquidity hook
    function afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata modifyLiquidityParams,
        BalanceDelta balanceDelta,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.AFTER_REMOVE_LIQUIDITY_FLAG,
            BaseHook.afterRemoveLiquidity.selector,
            abi.encodeWithSelector(
                BaseHook.afterRemoveLiquidity.selector,
                sender,
                key,
                modifyLiquidityParams,
                balanceDelta,
                removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called before donating
    /// @param sender The original sender of the before donate call
    /// @param key The pool key identifying the pool
    /// @param amount0 the amount of token0 to donate
    /// @param amount1 the amount of token1 to donate
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the beforeDonate hook
    function beforeDonate(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.BEFORE_DONATE_FLAG,
            BaseHook.beforeDonate.selector,
            abi.encodeWithSelector(
                BaseHook.beforeDonate.selector, sender, key, amount0, amount1, removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice Hook called after donating
    /// @param sender The original sender of the after donate call
    /// @param key The pool key identifying the pool
    /// @param amount0 the amount of token0 to donate
    /// @param amount1 the amount of token1 to donate
    /// @param hookData Encoded data including the pass-through hook address and additional data
    /// @return The function selector for the afterDonate hook
    function afterDonate(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external override returns (bytes4) {
        return _handleRouting(
            hookData,
            Hooks.AFTER_DONATE_FLAG,
            BaseHook.afterDonate.selector,
            abi.encodeWithSelector(
                BaseHook.afterDonate.selector, sender, key, amount0, amount1, removeFirst20Bytes(hookData)
            )
        );
    }

    /// @notice below are a series of methods to determine if the hook router
    /// has a hook allow list or a list of hooks to block and lets the owner
    /// add or remove hooks to each list if they should be checked
    function changeHasAllowList(bool _hasAllowList) external onlyOwner {
        hasHookAllowList = _hasAllowList;
    }

    function changeHasBlockList(bool _hasBlockList) external onlyOwner {
        hasHookBlockList = _hasBlockList;
    }

    function addToAllowList(address _passThroughHook) external onlyOwner {
        manageAllowList(_passThroughHook, true);
    }

    function removeFromAllowList(address _passThroughHook) external onlyOwner {
        manageAllowList(_passThroughHook, false);
    }

    function manageAllowList(address _passThroughHook, bool _isAllowed) internal {
        hookAllowList[_passThroughHook] = _isAllowed;
    }

    function addToBlockList(address _passThroughHook) external onlyOwner {
        manageBlockList(_passThroughHook, true);
    }

    function removeFromBlockList(address _passThroughHook) external onlyOwner {
        manageBlockList(_passThroughHook, false);
    }

    function manageBlockList(address _passThroughHook, bool _isBlocked) internal {
        hookBlockList[_passThroughHook] = _isBlocked;
    }

    /// @notice bubble up revert if present. Else throw FailedHookCall
    function _revert(bytes memory result) private pure {
        if (result.length == 0) revert FailedHookRouterCall();
        assembly {
            revert(add(0x20, result), mload(result))
        }
    }

    function removeFirst20Bytes(bytes memory data) internal pure returns (bytes memory) {
        if (data.length < 20) {
            return "";
        }
        bytes memory result = new bytes(data.length - 20);
        // Copy the data starting at byte 20
        for (uint256 i = 20; i < data.length; i++) {
            result[i - 20] = data[i];
        }
        return result;
    }
}
