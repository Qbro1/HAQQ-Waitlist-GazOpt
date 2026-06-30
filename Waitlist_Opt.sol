// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title Waitlist
 * @author Vorobevsa HAQQ Network (Optimized Version)
 * @notice Smart contract for collecting and storing participation applications before network upgrade.
 */
contract Waitlist is Ownable2Step, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============ State Machine ============

    enum RequestsState {
        Initialized, 
        Started, 
        Closed, 
        Finalized 
    }

    // ============ Request Structure ============

    enum FundsSource {
        OwnBalance, 
        ucDAO 
    }

    struct Request {
        uint256 amount;       
        address author;       
        FundsSource source; 
        uint40 cancelledAt;  
        uint40 createdAt;     
    }                        

    // ============ Storage Layout Optimization ============

   
    RequestsState public currentState;
    address public backendSigner;

    /// @notice Array of all requests (including cancelled ones)
    Request[] public requests;

    /// @notice Mapping from user address to request IDs
    mapping(address => uint256[]) public userRequests;

    /// @notice Mapping of manager addresses
    mapping(address => bool) public managers;

    /// @notice Mapping from user address to nonce (prevents signature replay attacks)
    mapping(address => uint256) public userNonces;

    /// @notice Total amount of active (non-cancelled) applications
    uint256 public totalActiveAmount;

    /// @notice Total count of active (non-cancelled) applications
    uint256 public totalActiveCount;

    // ============ Version ============

    string public constant VERSION = "0.7.0-optimized";

    // ============ Events ============

    event RequestCreated(
        uint256 indexed requestId,
        address indexed author,
        uint256 amount,
        FundsSource indexed source,
        uint256 createdAt,
        bytes backendSignature
    );
    event RequestCancelled(uint256 indexed requestId, address indexed author);
    event RequestsOpened();
    event RequestsClosed();
    event RequestsFinalized();
    event BackendSignerChanged(address indexed oldSigner, address indexed newSigner);
    event UserNonceIncremented(address indexed user, uint256 indexed oldNonce, uint256 indexed newNonce);
    event ManagerGranted(address indexed manager);
    event ManagerRevoked(address indexed manager);

    // ============ Custom Errors ============

    error InvalidInitialOwner();
    error InvalidManagerAddress();
    error AlreadyFinalized();
    error CannotOpenRequests();
    error CannotCloseRequests();
    error RequestsAlreadyFinalized();
    error CannotSubmitRequests();
    error AmountMustBeGreaterThanZero();
    error InvalidBackendSignature();
    error RequestDoesNotExist();
    error OnlyAuthorCanCancel();
    error RequestAlreadyCancelled();
    error CannotCancelInCurrentState();

    // ============ Modifiers ============

    modifier onlyOwnerOrManager() {
        _checkOwnerOrManager();
        _;
    }

    modifier notFinalized() {
        if (currentState == RequestsState.Finalized) {
            revert AlreadyFinalized();
        }
        _;
    }

    // ============ Constructor ============

    constructor(address initialOwner) Ownable(initialOwner) {
        if (initialOwner == address(0)) {
            revert InvalidInitialOwner();
        }
        currentState = RequestsState.Initialized;
    }

    // ============ State Management Functions ============

    function openRequests() external onlyOwnerOrManager whenNotPaused {
        if (currentState == RequestsState.Started) {
            revert CannotOpenRequests();
        }
        currentState = RequestsState.Started;
        emit RequestsOpened();
    }

    function closeRequests() external onlyOwnerOrManager whenNotPaused {
        if (currentState != RequestsState.Started) {
            revert CannotCloseRequests();
        }
        currentState = RequestsState.Closed;
        emit RequestsClosed();
    }

    function finalizeRequests() external onlyOwnerOrManager whenNotPaused {
        if (currentState == RequestsState.Finalized) {
            revert RequestsAlreadyFinalized();
        }
        if (currentState != RequestsState.Closed) {
            emit RequestsClosed();
        }
        currentState = RequestsState.Finalized;
        emit RequestsFinalized();
    }

    // ============ Request Management Functions ============

    /**
     * @notice Creates a new participation application
     */
    function createRequest(
        uint256 amount,
        FundsSource source,
        bytes calldata backendSignature
    ) external whenNotPaused {
        if (!canSubmit()) {
            revert CannotSubmitRequests();
        }
        if (amount == 0) {
            revert AmountMustBeGreaterThanZero();
        }

        if (backendSigner != address(0)) {
            uint256 nonce = userNonces[msg.sender];
            if (!verifyBackendSignature(msg.sender, amount, source, nonce, backendSignature)) {
                revert InvalidBackendSignature();
            }
            
            emit UserNonceIncremented(msg.sender, nonce, nonce + 1);
            
           
            unchecked {
                userNonces[msg.sender] = nonce + 1;
            }
        }

        
        uint256 requestId = requests.length;
        uint40 createdAt = uint40(block.timestamp);

        requests.push(Request({
            amount: amount,
            author: msg.sender,
            source: source,
            cancelledAt: 0,
            createdAt: createdAt
        }));

        userRequests[msg.sender].push(requestId);

        totalActiveAmount += amount;
        
        unchecked {
            ++totalActiveCount;
        }

        emit RequestCreated(
            requestId,
            msg.sender,
            amount,
            source,
            createdAt,
            backendSignature
        );
    }

    /**
     * @notice Cancels a request
     */
    function cancelRequest(uint256 requestId) external whenNotPaused notFinalized {
        
        if (requestId >= requests.length) {
            revert RequestDoesNotExist();
        }

        Request storage request = requests[requestId];

        if (request.author != msg.sender) {
            revert OnlyAuthorCanCancel();
        }
        if (request.cancelledAt != 0) {
            revert RequestAlreadyCancelled();
        }
        if (!canWithdraw()) {
            revert CannotCancelInCurrentState();
        }

        request.cancelledAt = uint40(block.timestamp);

        totalActiveAmount -= request.amount;
        
        
        unchecked {
            --totalActiveCount;
        }

        emit RequestCancelled(requestId, msg.sender);
    }

    // ============ View Functions ============

    function getTotalAmount() external view returns (uint256) {
        return totalActiveAmount;
    }

    function getTotalCount() external view returns (uint256) {
        return totalActiveCount;
    }

    function getRequestById(uint256 requestId) external view returns (Request memory) {
        if (requestId >= requests.length) {
            revert RequestDoesNotExist();
        }
        return requests[requestId];
    }

    function getRequestsByUser(address user) external view returns (uint256[] memory) {
        return userRequests[user];
    }

    function canSubmit() public view returns (bool) {
        return !paused() && currentState == RequestsState.Started;
    }

    function canWithdraw() public view returns (bool) {
        return !paused() && (currentState == RequestsState.Started || currentState == RequestsState.Closed);
    }

    function getTotalRequestsCount() external view returns (uint256) {
        return requests.length;
    }

    function version() external pure returns (string memory) {
        return VERSION;
    }

    function getUserNonce(address user) external view returns (uint256) {
        return userNonces[user];
    }

    // ============ Manager Role Management ============

    function grantManager(address manager) external onlyOwner {
        if (manager == address(0)) {
            revert InvalidManagerAddress();
        }
        managers[manager] = true;
        emit ManagerGranted(manager);
    }

    function revokeManager(address manager) external onlyOwner {
        managers[manager] = false;
        emit ManagerRevoked(manager);
    }

    // ============ Backend Signature Management ============

    function setBackendSigner(address newSigner) external onlyOwner {
        address oldSigner = backendSigner;
        backendSigner = newSigner;
        emit BackendSignerChanged(oldSigner, newSigner);
    }

    function verifyBackendSignature(
        address user,
        uint256 amount,
        FundsSource source,
        uint256 nonce,
        bytes calldata signature
    ) public view returns (bool) {
        bytes32 messageHash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                user,
                amount,
                source,
                nonce
            )
        );
        return messageHash.toEthSignedMessageHash().recover(signature) == backendSigner;
    }

    // ============ Internal Helpers ============

    
    function _checkOwnerOrManager() internal view {
        if (msg.sender != owner() && !managers[msg.sender]) {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
    }

    // ============ Ownership Functions ============

    function renounceOwnership() public virtual override onlyOwner {
        _transferOwnership(address(0));
    }

    // ============ Pause Functions ============

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}