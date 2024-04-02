// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {Counter} from "../src/Counter.sol";
import {DoubleCounter} from "../src/DoubleCounter.sol";
import {HookRouter} from "../src/HookRouter.sol";
import {HookMiner} from "./utils/HookMiner.sol";
import "forge-std/console.sol";

contract HookRouterTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    HookRouter hookRouter;
    Counter counter;
    DoubleCounter doubleCounter;
    PoolId poolId;

    function setUp() public {
        // creates the pool manager, utility routers, and test tokens
        Deployers.deployFreshManagerAndRouters();
        Deployers.deployMintAndApprove2Currencies();

        // Deploy the hook router to an address with the correct flags
        uint160 hookRouterFlags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG
                | Hooks.AFTER_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
                | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_DONATE_FLAG | Hooks.AFTER_DONATE_FLAG
        );
        (address hookRouterAddress, bytes32 hookRouterSalt) =
            HookMiner.find(address(this), hookRouterFlags, type(HookRouter).creationCode, abi.encode(address(manager)));
        hookRouter = new HookRouter{salt: hookRouterSalt}(IPoolManager(address(manager)));
        require(address(hookRouter) == hookRouterAddress, "HookRouterTest: hookRouter address mismatch");

        // Deploy the counter hook to an address with the correct flags
        uint160 hookCounterFlags = uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG
                | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG
        );
        (address hookCounterAddress, bytes32 hookCounterSalt) =
            HookMiner.find(address(this), hookCounterFlags, type(Counter).creationCode, abi.encode(address(manager)));
        counter = new Counter{salt: hookCounterSalt}(IPoolManager(address(manager)));
        require(address(counter) == hookCounterAddress, "HookRouterTest: hook counter address mismatch");

        // Deploy the doubleCounter hook to an address with the correct flags
        uint160 hookDoubleCounterFlags = uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG
                | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG
        );
        (address hookDoubleCounterAddress, bytes32 hookDoubleCounterSalt) = HookMiner.find(
            address(this), hookDoubleCounterFlags, type(DoubleCounter).creationCode, abi.encode(address(manager))
        );
        doubleCounter = new DoubleCounter{salt: hookDoubleCounterSalt}(IPoolManager(address(manager)));
        require(
            address(doubleCounter) == hookDoubleCounterAddress, "HookRouterTest: hook doubleCounter address mismatch"
        );

        // Create the pool
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(hookRouter)));
        poolId = key.toId();
        manager.initialize(key, SQRT_RATIO_1_1, ZERO_BYTES);

        // Provide liquidity to the pool
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-120, 120, 10 ether), abi.encodePacked(counter)
        );
        modifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams(TickMath.minUsableTick(60), TickMath.maxUsableTick(60), 10 ether),
            abi.encodePacked(counter)
        );
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(doubleCounter)
        );
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-120, 120, 10 ether), abi.encodePacked(doubleCounter)
        );
    }

    function testCounterHooksWithSwap() public {
        // positions were created in setup()
        assertEq(counter.beforeAddLiquidityCount(poolId), 3);
        assertEq(doubleCounter.beforeAddLiquidityCount(poolId), 4);

        assertEq(counter.beforeRemoveLiquidityCount(poolId), 0);
        assertEq(doubleCounter.beforeRemoveLiquidityCount(poolId), 0);

        assertEq(counter.beforeSwapCount(poolId), 0);
        assertEq(doubleCounter.beforeSwapCount(poolId), 0);

        assertEq(counter.afterSwapCount(poolId), 0);
        assertEq(doubleCounter.afterSwapCount(poolId), 0);

        // Perform a test swap //
        bool zeroForOne = true;
        int256 amountSpecified = -1e18; // negative number indicates exact input swap!
        BalanceDelta swapDelta = swap(key, zeroForOne, amountSpecified, abi.encodePacked(counter));
        // ------------------- //

        assertEq(int256(swapDelta.amount0()), amountSpecified);

        assertEq(counter.beforeSwapCount(poolId), 1);
        assertEq(doubleCounter.beforeSwapCount(poolId), 0);

        assertEq(counter.afterSwapCount(poolId), 1);
        assertEq(doubleCounter.afterSwapCount(poolId), 0);
    }

    function testCounterHooksWithRemoveLiquidity() public {
        // positions were created in setup()
        assertEq(counter.beforeAddLiquidityCount(poolId), 3);
        assertEq(doubleCounter.beforeAddLiquidityCount(poolId), 4);

        assertEq(counter.beforeRemoveLiquidityCount(poolId), 0);
        assertEq(doubleCounter.beforeRemoveLiquidityCount(poolId), 0);

        // remove liquidity
        int256 liquidityDelta = -1e18;
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, liquidityDelta), abi.encodePacked(doubleCounter)
        );

        assertEq(counter.beforeAddLiquidityCount(poolId), 3);
        assertEq(doubleCounter.beforeAddLiquidityCount(poolId), 4);

        assertEq(counter.beforeRemoveLiquidityCount(poolId), 0);
        assertEq(doubleCounter.beforeRemoveLiquidityCount(poolId), 2);
    }

    function testAllowListHooks() public {
        assertEq(counter.beforeAddLiquidityCount(poolId), 3);
        // set allow list to true but do not add any contracts
        hookRouter.changeHasAllowList(true);
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        // set allow list to false
        hookRouter.changeHasAllowList(false);
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        assertEq(counter.beforeAddLiquidityCount(poolId), 4);
        // set allow list to true and add counter to the allow list
        hookRouter.changeHasAllowList(true);
        hookRouter.addToAllowList(address(counter));
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        assertEq(counter.beforeAddLiquidityCount(poolId), 5);
        // double counter reverts as it is not on the allow list
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(doubleCounter)
        );
        hookRouter.changeHasAllowList(false);
    }

    function testBlockListHooks() public {
        assertEq(counter.beforeAddLiquidityCount(poolId), 3);
        // set block list to true but do not add any contracts
        hookRouter.changeHasBlockList(true);
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        assertEq(counter.beforeAddLiquidityCount(poolId), 4);
        hookRouter.changeHasBlockList(false);
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        assertEq(counter.beforeAddLiquidityCount(poolId), 5);
        // set Block list to true and add counter to the Block list causing a revert
        hookRouter.changeHasBlockList(true);
        hookRouter.addToBlockList(address(counter));
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(counter)
        );
        assertEq(counter.beforeAddLiquidityCount(poolId), 5);
        // double counter passes as it is not on the Block list
        assertEq(doubleCounter.beforeAddLiquidityCount(poolId), 4);
        modifyLiquidityRouter.modifyLiquidity(
            key, IPoolManager.ModifyLiquidityParams(-60, 60, 10 ether), abi.encodePacked(doubleCounter)
        );
        assertEq(doubleCounter.beforeAddLiquidityCount(poolId), 6);
        hookRouter.changeHasBlockList(false);
    }
}
