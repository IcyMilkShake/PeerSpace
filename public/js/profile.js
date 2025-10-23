let currentUser = null;
let posts = [];
let currentFilter = 'all';
let socket = io();
let profileUserId = null;
let currentSinglePostId = null;
let cropper = null;
let bannerCropper = null;
let avatarContainer;

// Gets the first letter of the first two words of a name.
function getInitials(name) {
    if (!name) return '?';
    return name.split(' ').map(word => word[0]).join('').toUpperCase().slice(0, 2);
}

// Creates a user profile image or a fallback with initials.
function createProfileImage(photoUrl, name, size = "w-10 h-10", textClass = "text-sm", borderClass = "") {
    const container = document.createElement('div');
    container.className = `profile-img ${size} ${borderClass} rounded-full flex items-center justify-center overflow-hidden`;
    container.style.backgroundColor = 'var(--input-field-bg)';

    if (borderClass && borderClass.includes('border')) {
        container.style.borderColor = 'var(--border-color-medium)';
    }

    if (photoUrl && photoUrl.trim() && photoUrl !== '/default-profile.png') {
        const img = document.createElement('img');
        img.className = 'w-full h-full object-cover';
        img.alt = name || 'Profile';

        img.onerror = function() {
            container.innerHTML = `<span class="profile-initials ${textClass} font-semibold" style="color: var(--text-secondary);">${getInitials(name)}</span>`;
        };
        img.src = photoUrl + '?t=' + Date.now();
        container.appendChild(img);
    } else {
        container.innerHTML = `<span class="profile-initials ${textClass} font-semibold" style="color: var(--text-secondary);">${getInitials(name)}</span>`;
    }
    return container;
}

// Initializes the image cropper.
function initializeCropper(imageElement) {
    if (cropper) {
        cropper.destroy();
        cropper = null;
    }
    cropper = new Cropper(imageElement, {
        aspectRatio: 1, viewMode: 1, dragMode: 'move', autoCropArea: 0.8,
        restore: false, guides: true, center: true, highlight: false,
        cropBoxMovable: true, cropBoxResizable: true, toggleDragModeOnDblclick: false,
        responsive: true, checkOrientation: false, modal: true, background: true,
        minContainerWidth: 200, minContainerHeight: 200,
    });
}

// Initializes the banner cropper.
function initializeBannerCropper(imageElement) {
    if (bannerCropper) {
        bannerCropper.destroy();
        bannerCropper = null;
    }
    bannerCropper = new Cropper(imageElement, {
        aspectRatio: 3 / 1, viewMode: 1, dragMode: 'move', autoCropArea: 0.8,
        restore: false, guides: true, center: true, highlight: false,
        cropBoxMovable: true, cropBoxResizable: true, toggleDragModeOnDblclick: false,
        responsive: true, checkOrientation: false, modal: true, background: true,
        minContainerWidth: 300, minContainerHeight: 100,
    });
}

// Handles the selection of a profile picture file.
function handleProfilePictureSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';

    if (!file.type.startsWith('image/')) {
        showNotification('Please select an image file', 'warning'); return;
    }
    if (file.size > 5 * 1024 * 1024) {
        showNotification('Image too large (max 5MB)', 'warning'); return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = () => {
            const MAX_WIDTH = 1000;
            const MAX_HEIGHT = 1000;
            let width = img.width;
            let height = img.height;

            if (width > height) {
                if (width > MAX_WIDTH) {
                    height *= MAX_WIDTH / width;
                    width = MAX_WIDTH;
                }
            } else {
                if (height > MAX_HEIGHT) {
                    width *= MAX_HEIGHT / height;
                    height = MAX_HEIGHT;
                }
            }

            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, width, height);
            const dataUrl = canvas.toDataURL('image/jpeg');

            const cropImage = document.getElementById('crop-image');
            if (cropper) cropper.destroy();
            cropImage.src = dataUrl;
            document.getElementById('crop-modal').classList.remove('hidden');
            const navUserModal = document.getElementById('user-profile-modal');
            if(navUserModal) navUserModal.classList.add('hidden');

            cropImage.onload = () => setTimeout(() => initializeCropper(cropImage), 100);
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// Handles the selection of a banner picture file.
function handleBannerPictureSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';

    if (!file.type.startsWith('image/')) {
        showNotification('Please select an image file', 'warning'); return;
    }
    if (file.size > 5 * 1024 * 1024) {
        showNotification('Image too large (max 5MB)', 'warning'); return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = () => {
            const MAX_WIDTH = 1500;
            const MAX_HEIGHT = 1500;
            let width = img.width;
            let height = img.height;

            if (width > height) {
                if (width > MAX_WIDTH) {
                    height *= MAX_WIDTH / width;
                    width = MAX_WIDTH;
                }
            } else {
                if (height > MAX_HEIGHT) {
                    width *= MAX_HEIGHT / height;
                    height = MAX_HEIGHT;
                }
            }

            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, width, height);
            const dataUrl = canvas.toDataURL('image/jpeg');

            const cropImage = document.getElementById('crop-image');
            if (bannerCropper) bannerCropper.destroy();
            cropImage.src = dataUrl;
            document.getElementById('crop-modal').classList.remove('hidden');
            const navUserModal = document.getElementById('user-profile-modal');
            if(navUserModal) navUserModal.classList.add('hidden');

            cropImage.onload = () => setTimeout(() => initializeBannerCropper(cropImage), 100);
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// Uploads the cropped image to the server.
async function uploadCroppedImage() {
    if (!cropper) { showNotification('Cropper not initialized.', 'error'); return; }
    const canvas = cropper.getCroppedCanvas({ width: 300, height: 300, imageSmoothingEnabled: true, imageSmoothingQuality: 'high' });
    if (!canvas) { showNotification('Failed to crop image.', 'error'); return; }

    return new Promise((resolve, reject) => {
        canvas.toBlob(async (blob) => {
            if (!blob) { reject(new Error('Blob creation failed')); return; }
            const formData = new FormData();
            formData.append('profilePicture', blob, 'profile.png');

            const uploadModal = document.getElementById('upload-modal');
            const progressBar = document.getElementById('upload-progress');
            uploadModal.classList.remove('hidden');
            progressBar.style.width = '0%';

            const xhr = new XMLHttpRequest();
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) progressBar.style.width = (e.loaded / e.total) * 100 + '%';
            };
            xhr.onload = () => {
                uploadModal.classList.add('hidden');
                if (xhr.status === 200) resolve(JSON.parse(xhr.responseText));
                else reject(new Error(`Upload failed: ${xhr.statusText}`));
            };
            xhr.onerror = () => {
                uploadModal.classList.add('hidden');
                reject(new Error('Upload network error'));
            };
            xhr.open('POST', '/user/profile-picture');
            xhr.send(formData);
        }, 'image/png', 0.9);
    });
}

// Uploads the cropped banner image to the server.
async function uploadCroppedBannerImage() {
    if (!bannerCropper) { showNotification('Banner cropper not initialized.', 'error'); return; }
    const canvas = bannerCropper.getCroppedCanvas({ width: 1500, height: 500, imageSmoothingEnabled: true, imageSmoothingQuality: 'high' });
    if (!canvas) { showNotification('Failed to crop banner image.', 'error'); return; }

    return new Promise((resolve, reject) => {
        canvas.toBlob(async (blob) => {
            if (!blob) { reject(new Error('Blob creation failed')); return; }
            const formData = new FormData();
            formData.append('bannerPicture', blob, 'banner.png');

            const uploadModal = document.getElementById('upload-modal');
            const progressBar = document.getElementById('upload-progress');
            uploadModal.classList.remove('hidden');
            progressBar.style.width = '0%';

            const xhr = new XMLHttpRequest();
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) progressBar.style.width = (e.loaded / e.total) * 100 + '%';
            };
            xhr.onload = () => {
                uploadModal.classList.add('hidden');
                if (xhr.status === 200) resolve(JSON.parse(xhr.responseText));
                else reject(new Error(`Upload failed: ${xhr.statusText}`));
            };
            xhr.onerror = () => {
                uploadModal.classList.add('hidden');
                reject(new Error('Upload network error'));
            };
            xhr.open('POST', '/user/banner-picture');
            xhr.send(formData);
        }, 'image/png', 0.9);
    });
}

// --- WebRTC & Socket.IO Globals ---
let localStream = null;
let peerConnections = {}; // key: socketId, value: RTCPeerConnection
let currentVoiceChannel = null; // { id: 'channelId', participants: [] }
let audioContext, meter, speakingTimer;
let isSpeaking = false;


// Create a container for remote audio elements that will be hidden
const remoteAudioContainer = document.createElement('div');
remoteAudioContainer.id = 'remote-audio-container';
remoteAudioContainer.style.display = 'none';
document.body.appendChild(remoteAudioContainer);

socket.on('update-participants', (participants) => {
    if (!currentVoiceChannel) return;
    currentVoiceChannel.participants = participants;

    // --- Update the main voice channel UI (in the post/comment) ---
    const participantsDiv = document.getElementById(`voice-participants-${currentVoiceChannel.id}`);
    if (participantsDiv) {
        participantsDiv.innerHTML = '';
        if (participants.length === 0) {
            participantsDiv.innerHTML = '<span class="text-sm text-gray-500 pl-2">No one is here yet.</span>';
        } else {
            participants.forEach(p => {
                const pfp = createProfileImage(p.profilePicture ? p.profilePicture.path : null, p.displayName, 'w-8 h-8', 'text-xs', 'border-2 border-white dark:border-gray-800');
                pfp.title = p.displayName;
                pfp.dataset.socketId = p.socketId;
                participantsDiv.appendChild(pfp);
            });
        }
    }

    // --- Update desktop floating voice chat panel ---
    const desktopPanelParticipantsList = document.getElementById('desktop-voice-chat-participants-list');
    if (desktopPanelParticipantsList) {
        desktopPanelParticipantsList.innerHTML = '';
        participants.forEach(p => {
            const participantEl = document.createElement('div');
            participantEl.className = 'flex items-center justify-between text-sm';

            const userInfo = document.createElement('div');
            userInfo.className = 'flex items-center space-x-2';
            const pfp = createProfileImage(p.profilePicture ? p.profilePicture.path : null, p.displayName, 'w-6 h-6', 'text-xs');
            pfp.dataset.socketId = p.socketId;
            userInfo.appendChild(pfp);
            const name = document.createElement('span');
            name.textContent = p.displayName;
            userInfo.appendChild(name);

            participantEl.appendChild(userInfo);

            if (p.socketId !== socket.id) {
                const volumeControl = document.createElement('button');
                volumeControl.className = 'text-gray-400 hover:text-white';
                volumeControl.innerHTML = '<i class="fas fa-volume-up"></i>';
                volumeControl.onclick = () => {
                    const audioEl = document.getElementById(`remote-audio-${p.socketId}`);
                    if (audioEl) {
                        audioEl.muted = !audioEl.muted;
                        volumeControl.innerHTML = `<i class="fas ${audioEl.muted ? 'fa-volume-mute' : 'fa-volume-up'}"></i>`;
                    }
                };
                participantEl.appendChild(volumeControl);
            }

            desktopPanelParticipantsList.appendChild(participantEl);
        });
    }

    // --- Update mobile floating voice chat panel ---
    const mobilePanelParticipantsList = document.getElementById('mobile-voice-chat-participants-list');
    if (mobilePanelParticipantsList) {
        mobilePanelParticipantsList.innerHTML = '';
        participants.forEach(p => {
            const pfp = createProfileImage(p.profilePicture ? p.profilePicture.path : null, p.displayName, 'w-8 h-8', 'text-xs', 'border-2 border-gray-600');
            pfp.title = p.displayName;
            pfp.dataset.socketId = p.socketId;

            if (p.socketId !== socket.id) {
                pfp.style.cursor = 'pointer';
                pfp.onclick = () => {
                    const audioEl = document.getElementById(`remote-audio-${p.socketId}`);
                    if (audioEl) {
                        audioEl.muted = !audioEl.muted;
                        if (audioEl.muted) {
                            pfp.classList.add('muted-pfp');
                        } else {
                            pfp.classList.remove('muted-pfp');
                        }
                    }
                };
                // Check initial muted state
                const audioEl = document.getElementById(`remote-audio-${p.socketId}`);
                if (audioEl && audioEl.muted) {
                    pfp.classList.add('muted-pfp');
                }
            }

            mobilePanelParticipantsList.appendChild(pfp);
        });
    }
});

socket.on('user-left', ({ socketId }) => {
    if (peerConnections[socketId]) {
        peerConnections[socketId].close();
        delete peerConnections[socketId];
    }
    const audioEl = document.getElementById(`remote-audio-${socketId}`);
    if (audioEl) {
        audioEl.remove();
    }
});

socket.on('voice-channel-updated', ({ channelId, participants }) => {
    const participantElements = document.querySelectorAll(`#voice-participants-${channelId}`);

    participantElements.forEach(participantsDiv => {
        if (participantsDiv) {
            participantsDiv.innerHTML = ''; // Clear existing content
            if (participants.length === 0) {
                participantsDiv.innerHTML = '<span class="text-sm text-gray-500 pl-2">No one is here yet.</span>';
            } else {
                participants.forEach(p => {
                    const pfp = createProfileImage(p.profilePicture ? p.profilePicture.path : null, p.displayName, 'w-8 h-8', 'text-xs', 'border-2 border-white dark:border-gray-800');
                    pfp.title = p.displayName;
                    pfp.dataset.socketId = p.socketId;
                    participantsDiv.appendChild(pfp);
                });
            }
        }
    });
});

const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
    ]
};

function createPeerConnection(targetSocketId) {
    const pc = new RTCPeerConnection(rtcConfig);

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            socket.emit('ice-candidate', {
                targetSocketId: targetSocketId,
                candidate: event.candidate,
            });
        }
    };

    pc.ontrack = (event) => {
        const remoteAudioContainer = document.getElementById('remote-audio-container');
        let audio = document.getElementById(`remote-audio-${targetSocketId}`);
        if (!audio) {
            audio = document.createElement('audio');
            audio.id = `remote-audio-${targetSocketId}`;
            audio.className = 'remote-audio';
            audio.autoplay = true;
            remoteAudioContainer.appendChild(audio);
        }
        audio.srcObject = event.streams[0];
    };

    if (localStream) {
        localStream.getTracks().forEach(track => {
            pc.addTrack(track, localStream);
        });
    }

    peerConnections[targetSocketId] = pc;
    return pc;
}

socket.on('existing-participants', ({ participants }) => {
    participants.forEach(async (p) => {
        const pc = createPeerConnection(p.socketId);
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        socket.emit('offer', {
            targetSocketId: p.socketId,
            offer: pc.localDescription
        });
    });
});

socket.on('offer', async ({ fromSocketId, offer }) => {
    const pc = createPeerConnection(fromSocketId);
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit('answer', {
        targetSocketId: fromSocketId,
        answer: pc.localDescription,
    });
});

socket.on('answer', async ({ fromSocketId, answer }) => {
    const pc = peerConnections[fromSocketId];
    if (pc) {
        await pc.setRemoteDescription(new RTCSessionDescription(answer));
    }
});

socket.on('ice-candidate', async ({ fromSocketId, candidate }) => {
    const pc = peerConnections[fromSocketId];
    if (pc && candidate) {
        try {
            await pc.addIceCandidate(new RTCIceCandidate(candidate));
        } catch (error) {
            console.error('Error adding received ice candidate', error);
        }
    }
});

socket.on('speaking', ({ socketId }) => {
    document.querySelectorAll(`[data-socket-id="${socketId}"]`).forEach(el => {
        el.classList.add('speaking');
    });
});

socket.on('stopped-speaking', ({ socketId }) => {
    document.querySelectorAll(`[data-socket-id="${socketId}"]`).forEach(el => {
        el.classList.remove('speaking');
    });
});

socket.on('channel-full', () => {
    showNotification('This voice channel is full and cannot be joined at this time.', 'error');
    leaveVoiceChannel();
});

async function createAudioMeter(stream, onVolumeChange) {
    audioContext = new (window.AudioContext || window.webkitAudioContext)();
    audioContext.resume();
    const source = audioContext.createMediaStreamSource(stream);

    try {
        await audioContext.audioWorklet.addModule('volume-meter.js');
        const meterNode = new AudioWorkletNode(audioContext, 'volume-meter-processor');
        meterNode.port.onmessage = event => {
            if (event.data.volume) {
                onVolumeChange(event.data.volume);
            }
        }
        source.connect(meterNode).connect(audioContext.destination);
    } catch (e) {
        console.error('Error setting up audio worklet.', e);
    }
}

async function joinVoiceChannel(channelId) {
    if (!currentUser) {
        return showNotification('You must be logged in to join a voice channel.', 'warning');
    }
    if (currentVoiceChannel) {
        return showNotification('You are already in a voice channel.', 'warning');
    }

    try {
        const audioConstraints = { audio: true, video: false };
        if (currentUser.audioSettings && currentUser.audioSettings.inputDevice) {
            audioConstraints.audio = { deviceId: { exact: currentUser.audioSettings.inputDevice } };
        }
        localStream = await navigator.mediaDevices.getUserMedia(audioConstraints);
    } catch (error) {
        console.error('Error accessing microphone:', error);
        return showNotification('Could not access microphone. Please grant permission.', 'error');
    }

    await createAudioMeter(localStream, (volume) => {
        const speakingThreshold = 0.02;
        if (volume > speakingThreshold) {
            clearTimeout(speakingTimer);
            speakingTimer = null;
            if (!isSpeaking) {
                isSpeaking = true;
                socket.emit('speaking');
                document.querySelectorAll(`[data-socket-id="${socket.id}"]`).forEach(el => {
                    el.classList.add('speaking');
                });
            }
        } else { // volume <= threshold
            if (isSpeaking && !speakingTimer) {
                speakingTimer = setTimeout(() => {
                    isSpeaking = false;
                    socket.emit('stopped-speaking');
                    document.querySelectorAll(`[data-socket-id="${socket.id}"]`).forEach(el => {
                        el.classList.remove('speaking');
                    });
                    speakingTimer = null;
                }, 500);
            }
        }
    });

    currentVoiceChannel = { id: channelId, participants: [] };
    sessionStorage.setItem('inVoiceChannel', channelId);
    createDesktopVoiceControlsUI(channelId);
    createMobileVoiceControlsUI(channelId);

    // We need to wait for the socket to be connected before emitting
    socket.emit('join-channel', { channelId, userId: currentUser.id });
}

function leaveVoiceChannel() {
    if (!currentVoiceChannel) return;
    const channelId = currentVoiceChannel.id;

    socket.emit('leave-channel');

    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
    }
    if (audioContext) {
        audioContext.close();
        audioContext = null;
    }
    clearTimeout(speakingTimer);
    isSpeaking = false;

    Object.values(peerConnections).forEach(pc => pc.close());
    peerConnections = {};

    const desktopPanel = document.getElementById('desktop-voice-panel');
    if (desktopPanel) {
        desktopPanel.remove();
    }
    const mobilePanel = document.getElementById('mobile-voice-panel');
    if (mobilePanel) {
        mobilePanel.remove();
    }

    const remoteAudioContainer = document.getElementById('remote-audio-container');
    if (remoteAudioContainer) {
        remoteAudioContainer.innerHTML = '';
    }

    fetch(`/${channelId}/voice-channel`)
        .then(res => res.json())
        .then(participants => {
            const participantsDiv = document.getElementById(`voice-participants-${channelId}`);
            if (participantsDiv) {
                participantsDiv.innerHTML = '';
                if (participants.length === 0) {
                    participantsDiv.innerHTML = '<span class="text-sm text-gray-500 pl-2">No one is here yet.</span>';
                } else {
                    participants.forEach(p => {
                        const pfp = createProfileImage(p.profilePicture ? p.profilePicture.path : null, p.displayName, 'w-8 h-8', 'text-xs', 'border-2 border-white dark:border-gray-800');
                        pfp.title = p.displayName;
                        pfp.dataset.socketId = p.socketId;
                        participantsDiv.appendChild(pfp);
                    });
                }
            }
        });

    currentVoiceChannel = null;
    sessionStorage.removeItem('inVoiceChannel');
    sessionStorage.removeItem('voiceChannelRefresh');
}

async function deleteVoiceChannel(channelId, itemType, itemId) {
    if (!currentUser) return;

    showConfirmationDialog(
        "Are you sure you want to delete this voice channel? This action cannot be undone.",
        async () => {
            try {
                const response = await fetch(`/${channelId}/voice-channel`, {
                    method: 'DELETE',
                });
                if (response.ok) {
                    // Optimistic update

                    const voiceChannelElement = document.querySelector(`.voice-channel-container #voice-participants-${channelId}`);
                    if (voiceChannelElement) {
                        voiceChannelElement.closest('.voice-channel-container').remove();
                    }
                    leaveVoiceChannel()
                    // Update local data
                    if (itemType === 'post') {
                        const postIndex = posts.findIndex(p => p.id === itemId);
                        if (postIndex !== -1) {
                            posts[postIndex].voiceChannel = null;
                        }
                    } else if (itemType === 'comment') {
                        for (const p of posts) {
                            const found = findComment(p.comments, itemId);
                            if (found) {
                                found.voiceChannel = null;
                                break;
                            }
                        }
                    }
                    showNotification('Voice channel deleted.', 'success');
                } else {
                    const errorData = await response.json().catch(() => ({ error: "Server error" }));
                    showNotification(`Failed to delete voice channel: ${errorData.error}`, 'error');
                }
            } catch (error) {
                console.error('Error deleting voice channel:', error);
                showNotification('An error occurred while deleting the voice channel.', 'error');
            }
        },
        null,
        "Delete Voice Channel"
    );
}

function createDesktopVoiceControlsUI(channelId) {
    let panel = document.getElementById('desktop-voice-panel');
    if (panel) {
        panel.remove();
    }

    panel = document.createElement('div');
    panel.id = 'desktop-voice-panel';
    panel.className = 'fixed bottom-4 right-4 bg-gray-800 text-white rounded-lg shadow-lg w-64 flex-col z-[101]';

    panel.innerHTML = `
        <div class="p-3 border-b border-gray-700">
            <p class="font-bold text-sm">Voice Connected</p>
            <p class="text-xs text-gray-400 truncate">Channel: ${channelId}</p>
        </div>
        <div id="desktop-voice-chat-participants-list" class="flex-grow p-3 space-y-2 overflow-y-auto" style="max-height: 200px;">
            <!-- Participants will be dynamically added here -->
        </div>
        <div class="p-2 bg-gray-900 rounded-b-lg flex items-center justify-around">
             <button id="desktop-mute-btn" class="hover:bg-gray-700 p-2 rounded-full" title="Mute/Unmute">
                <i class="fas fa-microphone"></i>
            </button>
            <button id="desktop-deafen-btn" data-deafened="false" class="hover:bg-gray-700 p-2 rounded-full" title="Deafen/Undeafen">
                <i class="fas fa-volume-up"></i>
            </button>
            <button onclick="leaveVoiceChannel()" class="bg-red-600 hover:bg-red-700 text-white p-2 rounded-full" title="Disconnect">
                <i class="fas fa-phone-slash"></i>
            </button>
        </div>
    `;
    document.body.appendChild(panel);

    const muteBtn = document.getElementById('desktop-mute-btn');
    muteBtn.addEventListener('click', () => {
        if (!localStream) return;
        const enabled = localStream.getAudioTracks()[0].enabled;
        localStream.getAudioTracks()[0].enabled = !enabled;
        muteBtn.innerHTML = `<i class="fas ${!enabled ? 'fa-microphone' : 'fa-microphone-slash'}"></i>`;
    });

    const deafenBtn = document.getElementById('desktop-deafen-btn');
    deafenBtn.addEventListener('click', () => {
        const audioElements = document.querySelectorAll('audio.remote-audio');
        const isDeafened = deafenBtn.dataset.deafened === 'true';
        audioElements.forEach(audio => {
            audio.muted = !isDeafened;
        });
        deafenBtn.dataset.deafened = !isDeafened;
        deafenBtn.innerHTML = `<i class="fas ${!isDeafened ? 'fa-volume-mute' : 'fa-volume-up'}"></i>`;
    });
}

function createMobileVoiceControlsUI(channelId) {
    let panel = document.getElementById('mobile-voice-panel');
    if (panel) {
        panel.remove();
    }

    panel = document.createElement('div');
    panel.id = 'mobile-voice-panel';
    panel.className = 'fixed bottom-4 right-4 bg-gray-800 text-white rounded-lg shadow-lg p-2 flex items-center space-x-4 z-[101]';

    panel.innerHTML = `
        <div id="mobile-voice-chat-participants-list" class="flex items-center space-x-1 overflow-hidden pr-2">
            <!-- Participants will be dynamically added here -->
        </div>
        <div class="flex items-center justify-around space-x-2">
             <button id="mobile-mute-btn" class="hover:bg-gray-700 p-2 rounded-full" title="Mute/Unmute">
                <i class="fas fa-microphone"></i>
            </button>
            <button id="mobile-deafen-btn" data-deafened="false" class="hover:bg-gray-700 p-2 rounded-full" title="Deafen/Undeafen">
                <i class="fas fa-volume-up"></i>
            </button>
            <button onclick="leaveVoiceChannel()" class="bg-red-600 hover:bg-red-700 text-white p-2 rounded-full" title="Disconnect">
                <i class="fas fa-phone-slash"></i>
            </button>
        </div>
    `;
    document.body.appendChild(panel);

    const muteBtn = document.getElementById('mobile-mute-btn');
    muteBtn.addEventListener('click', () => {
        if (!localStream) return;
        const enabled = localStream.getAudioTracks()[0].enabled;
        localStream.getAudioTracks()[0].enabled = !enabled;
        muteBtn.innerHTML = `<i class="fas ${!enabled ? 'fa-microphone' : 'fa-microphone-slash'}"></i>`;
    });

    const deafenBtn = document.getElementById('mobile-deafen-btn');
    deafenBtn.addEventListener('click', () => {
        const audioElements = document.querySelectorAll('audio.remote-audio');
        const isDeafened = deafenBtn.dataset.deafened === 'true';
        audioElements.forEach(audio => {
            audio.muted = !isDeafened;
        });
        deafenBtn.dataset.deafened = !isDeafened;
        deafenBtn.innerHTML = `<i class="fas ${!isDeafened ? 'fa-volume-mute' : 'fa-volume-up'}"></i>`;
    });
}

function findComment(comments, commentId) {
    for (const c of comments) {
        if (c.id === commentId || c._id === commentId) {
            return c;
        }
        if (c.replies) {
            const found = findComment(c.replies, commentId);
            if (found) {
                return found;
            }
        }
    }
    return null;
}

// Checks if a user is logged in on the profile page.
async function checkAuthStatusForProfilePage() {
    try {
        const response = await fetch('/user', { credentials: 'include' });
        if (response.ok) {
            currentUser = await response.json();
        } else {
            currentUser = null;
        }
    } catch (error) {
        console.error('Auth check failed on profile page:', error);
        currentUser = null;
    }
    updateProfilePageNav();
}

// Updates the navigation bar based on the user's login status.
function updateProfilePageNav() {
    const authSection = document.getElementById('auth-section-profile');
    const userProfileDropdown = document.getElementById('user-profile-dropdown-profile');

    if (currentUser) {
        const navProfileImg = createProfileImage(currentUser.photo, currentUser.name, "w-8 h-8", "text-xs");

        authSection.innerHTML = `
            <button onclick="toggleProfileDropdown()" class="nav-profile-button-hover flex items-center space-x-2 p-1 rounded-lg transition-colors">
                <div id="nav-profile-img-container-profile-page"></div>
                <span class="font-medium text-sm">${escapeHtml(currentUser.displayName)}</span>
            </button>
        `;
        document.getElementById('nav-profile-img-container-profile-page').appendChild(navProfileImg);

        const modalImgContainer = document.getElementById('modal-profile-img-container-profile');
        modalImgContainer.innerHTML = '';
        modalImgContainer.appendChild(createProfileImage(currentUser.photo, currentUser.displayName, "w-10 h-10", "text-base", "border-2"));

        document.getElementById('modal-user-name-profile').textContent = currentUser.displayName;
        const userEmailElem = document.getElementById('modal-user-email-profile');
        userEmailElem.textContent = currentUser.email;
        userEmailElem.classList.add('truncate');

        const profileMenuLink = document.getElementById('profile-menu-profile-page');
        if (profileMenuLink) {
            profileMenuLink.href = `profile.html?id=${currentUser.id}`;
        }

        const logoutBtn = document.getElementById('logout-btn-profile-page');
        logoutBtn.removeEventListener('click', logoutFromProfilePage);
        logoutBtn.addEventListener('click', logoutFromProfilePage);

    } else {
        authSection.innerHTML = '<a href="/" id="back-to-forum-link-profile" class="hover:underline">Back to Forum</a>';
        if (userProfileDropdown) userProfileDropdown.classList.add('hidden');
    }
}

// Shows or hides the profile dropdown menu.
function toggleProfileDropdown() {
    const userProfileDropdown = document.getElementById('user-profile-dropdown-profile');
    if (!currentUser || !userProfileDropdown) return;
    userProfileDropdown.classList.toggle('hidden');
}

// Logs the user out from the profile page.
async function logoutFromProfilePage() {
    try {
        await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
        currentUser = null;
        updateProfilePageNav();
        window.location.href = '/';
    } catch (error) {
        console.error('Logout failed:', error);
        showNotification('Logout failed. Please try again.', 'error');
    }
}

function getActiveVoiceChannelInfo() {
    if (!currentUser) return null;

    const findChannelInComments = (comments, postId) => {
        for (const comment of comments) {
            if (comment.voiceChannel && comment.voiceChannel.creator && comment.voiceChannel.creator.toString() === currentUser.id) {
                return { postId: postId, channelId: comment.voiceChannel._id };
            }
            if (comment.replies) {
                const found = findChannelInComments(comment.replies, postId);
                if (found) return found;
            }
        }
        return null;
    };

    for (const post of posts) {
        if (post.voiceChannel && post.voiceChannel.creator && post.voiceChannel.creator.toString() === currentUser.id) {
            return { postId: post.id, channelId: post.voiceChannel._id };
        }
        if (post.comments) {
            const foundInComment = findChannelInComments(post.comments, post.id);
            if (foundInComment) return foundInComment;
        }
    }

    return null;
}

function createVoiceChannelElement(item) {
    const voiceChannel = item.voiceChannel;
    if (!voiceChannel) return null;
    const channelId = voiceChannel._id;

    const container = document.createElement('div');
    container.className = 'voice-channel-container border rounded-lg p-4 flex items-center justify-between';
    container.innerHTML = `
        <div class="flex-grow">
            <h4 class="font-bold text-lg">${escapeHtml(voiceChannel.name || 'Voice Channel')}</h4>
            <div id="voice-participants-${channelId}" class="flex items-center -space-x-2 overflow-hidden">
                <span class="text-sm text-gray-500 pl-2">Loading participants...</span>
            </div>
        </div>
        <div id="voice-channel-buttons-${channelId}" class="flex items-center space-x-2 flex-shrink-0">
            <button onclick="joinVoiceChannel('${channelId}')" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg font-medium transition-colors">
                <i class="fas fa-phone-alt mr-2"></i>Join
            </button>
        </div>
    `;
    container.onclick = (e) => e.stopPropagation();

    const participantsDiv = container.querySelector(`#voice-participants-${channelId}`);
    const buttonsContainer = container.querySelector(`#voice-channel-buttons-${channelId}`);

    if (currentUser && voiceChannel.creator && currentUser.id === voiceChannel.creator.toString()) {
        const deleteButton = document.createElement('button');
        deleteButton.onclick = (e) => {
            e.stopPropagation();
            const itemType = item.title ? 'post' : 'comment'; // Heuristic to determine item type
            deleteVoiceChannel(channelId, itemType, item.id);
        };
        deleteButton.className = 'bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-medium transition-colors';
        deleteButton.innerHTML = `<i class="fas fa-trash-alt"></i>`;
        deleteButton.title = "Delete Voice Channel";
        buttonsContainer.appendChild(deleteButton);
    }

    fetch(`/${channelId}/voice-channel`)
        .then(res => res.json())
        .then(participants => {
            if (participantsDiv) {
                participantsDiv.innerHTML = '';
                if (participants.length === 0) {
                    participantsDiv.innerHTML = '<span class="text-sm text-gray-500 pl-2">No one is here yet.</span>';
                } else {
                    participants.forEach(p => {
                        const pfp = createProfileImage(p.profilePicture ? p.profilePicture.path : null, p.displayName, 'w-8 h-8', 'text-xs', 'border-2 border-white dark:border-gray-800');
                        pfp.title = p.displayName;
                        pfp.dataset.socketId = p.socketId;
                        participantsDiv.appendChild(pfp);
                    });
                }
            }
        })
        .catch(err => {
            console.error(`Failed to fetch participants for channel ${channelId}`, err);
            if (participantsDiv) {
                participantsDiv.innerHTML = '<span class="text-sm text-gray-500 pl-2">Error loading participants.</span>';
            }
        });

    return container;
}

async function createVoiceChannel(type, id) {
    if (!currentUser) {
        showNotification("Please sign in to create a voice channel.", "warning");
        return;
    }

    const activeChannelInfo = getActiveVoiceChannelInfo();
    if (activeChannelInfo) {
        const postId = activeChannelInfo.postId;
        showNotification(
            'You already have a voice channel open. Click here to go to it.',
            'warning',
            5000,
            () => {
                window.location.href = `/?post=${postId}`;
            }
        );
        return;
    }

    const nameVcModalOverlay = document.getElementById('name-vc-modal-overlay');
    const nameVcModalCancelBtn = document.getElementById('name-vc-modal-cancel-btn');
    const nameVcModalConfirmBtn = document.getElementById('name-vc-modal-confirm-btn');
    const vcNameInput = document.getElementById('vc-name-input');

    nameVcModalOverlay.classList.remove('hidden');

    const onConfirm = async () => {
        const name = vcNameInput.value.trim();
        if (!name) {
            showNotification("Please enter a name for the voice channel.", "warning");
            return;
        }

        let url;
        if (type === 'post') {
            url = `/posts/${id}/voice-channel`;
        } else if (type === 'comment') {
            url = `/comments/${id}/voice-channel`;
        } else {
            return;
        }

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            if (response.ok) {
                const data = await response.json();
                showNotification("Voice channel created successfully!", "success");
            } else {
                if (response.status === 409) {
                    const errorData = await response.json();
                    const postId = errorData.postId;
                    if (postId) {
                        showNotification(
                            'You already have a voice channel open. Click here to go to it.',
                            'warning',
                            5000,
                            () => {
                                window.location.href = `/?post=${postId}`;
                            }
                        );
                    } else {
                        showNotification(errorData.error || 'You already have a voice channel open.', 'error');
                    }
                } else {
                    const errorData = await response.json();
                    showNotification(`Error: ${errorData.error || 'Failed to create voice channel.'}`, 'error');
                }
            }
        } catch (error) {
            console.error(`Error creating voice channel for ${type} ${id}:`, error);
            showNotification('An error occurred while creating the voice channel.', 'error');
        } finally {
            closeNameVcModal();
        }
    };

    const onCancel = () => {
        closeNameVcModal();
    };

    const closeNameVcModal = () => {
        nameVcModalOverlay.classList.add('hidden');
        vcNameInput.value = '';
        nameVcModalConfirmBtn.removeEventListener('click', onConfirm);
        nameVcModalCancelBtn.removeEventListener('click', onCancel);
    };

    nameVcModalConfirmBtn.addEventListener('click', onConfirm);
    nameVcModalCancelBtn.addEventListener('click', onCancel);
}

function closeAllPostActionMenus() {
    document.querySelectorAll('.post-action-menu').forEach(menu => {
        menu.classList.add('hidden');
    });
}

function escapeHtml(text, allowLinks = false) {
    let escapedText = text.replace(/[&<>"']/g, function (match) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[match];
    });

    if (allowLinks) {
        const urlRegex = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])|(\bwww\.[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
        escapedText = escapedText.replace(urlRegex, function(url) {
            let fullUrl = url;
            if (!url.match(/^[a-zA-Z]+:\/\//)) {
                fullUrl = 'http://' + url;
            }
            const safeHref = fullUrl.replace(/[&<>"']/g, function (match) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[match];
            });
            return `<a href="${safeHref}" target="_blank" rel="noopener noreferrer">${url}</a>`;
        });

        const mentionWithIdRegex = /@([\w.-]+)\[([a-f\d]{24})\]/g;
        escapedText = escapedText.replace(mentionWithIdRegex, (match, username, userId) => {
            return `<a href="/profile.html?id=${userId}" class="mention-link" onclick="event.stopPropagation()">@${username}</a>`;
        });

        const oldMentionRegex = /@([\w.-]+)(?!\[[a-f\d]{24}\])/g;
        escapedText = escapedText.replace(oldMentionRegex, (match, username) => {
            return `<a href="/profile.html?username=${username}" class="mention-link" onclick="event.stopPropagation()">${match}</a>`;
        });
    }
    return escapedText;
}

// Gets the user ID or username from the URL.
function getUserIdFromUrl() {
    const params = new URLSearchParams(window.location.search);
    return params.get('id') || params.get('username');
}

// Formats a date string into a more readable format.
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

// Handles the logic for when a user types @ to mention someone.
function handleMention(textarea) {
    currentTextarea = textarea;
    const text = textarea.value;
    const cursorPos = textarea.selectionStart;
    const atIndex = text.lastIndexOf('@', cursorPos - 1);

    if (atIndex === -1) {
        hideSuggestions();
        return;
    }

    mentionStartIndex = atIndex;
    mentionQuery = text.substring(atIndex + 1, cursorPos);

    if (mentionQuery.includes(' ')) {
        hideSuggestions();
        return;
    }

    fetchUsers(mentionQuery);
}

// Fetches a list of users that match the mention query.
async function fetchUsers(query) {
    try {
        const response = await fetch(`/user/search?query=${query}`);
        mentionSuggestions = await response.json();
        showSuggestions();
    } catch (error) {
        console.error('Error fetching users:', error);
        hideSuggestions();
    }
}

// Shows the suggestions for user mentions.
function showSuggestions() {
    const suggestionsBox = document.getElementById('mentions-suggestions') || createSuggestionsBox();
    suggestionsBox.innerHTML = '';

    if (mentionSuggestions.length === 0) {
        hideSuggestions();
        return;
    }

    mentionSuggestions.forEach((user, index) => {
        const div = document.createElement('div');
        div.innerHTML = `
            <div class="font-bold">${user.displayName}</div>
            <div class="text-sm text-gray-500">@${user.username}</div>
        `;
        div.onclick = () => selectSuggestion(index);
        suggestionsBox.appendChild(div);
    });

    const rect = currentTextarea.getBoundingClientRect();
    suggestionsBox.style.top = `${rect.bottom + window.scrollY}px`;
    suggestionsBox.style.left = `${rect.left + window.scrollX}px`;
    suggestionsBox.style.display = 'block';
    activeSuggestionIndex = -1;
}

// Hides the user mention suggestions.
function hideSuggestions() {
    const suggestionsBox = document.getElementById('mentions-suggestions');
    if (suggestionsBox) {
        suggestionsBox.style.display = 'none';
    }
}

// Creates the suggestions box if it doesn't exist.
function createSuggestionsBox() {
    const suggestionsBox = document.createElement('div');
    suggestionsBox.id = 'mentions-suggestions';
    suggestionsBox.className = 'mentions-suggestions';
    document.body.appendChild(suggestionsBox);
    return suggestionsBox;
}

function selectSuggestion(index) {
    if (index < 0 || index >= mentionSuggestions.length) return;

    const user = mentionSuggestions[index];
    const text = currentTextarea.value;
    const before = text.substring(0, mentionStartIndex);
    const after = text.substring(currentTextarea.selectionStart);

    currentTextarea.value = `${before}@${user.username}[${user._id}] ${after}`;
    hideSuggestions();
    currentTextarea.focus();
}

document.addEventListener('keydown', (e) => {
    const suggestionsBox = document.getElementById('mentions-suggestions');
    if (!suggestionsBox || suggestionsBox.style.display === 'none') return;

    if (e.key === 'ArrowDown') {
        e.preventDefault();
        activeSuggestionIndex = (activeSuggestionIndex + 1) % mentionSuggestions.length;
        updateActiveSuggestion();
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        activeSuggestionIndex = (activeSuggestionIndex - 1 + mentionSuggestions.length) % mentionSuggestions.length;
        updateActiveSuggestion();
    } else if (e.key === 'Enter') {
        e.preventDefault();
        selectSuggestion(activeSuggestionIndex);
    } else if (e.key === 'Escape') {
        hideSuggestions();
    }
});

window.addEventListener('scroll', () => {
    hideSuggestions();
});

// Updates the currently highlighted user mention suggestion.
function updateActiveSuggestion() {
    const suggestionsBox = document.getElementById('mentions-suggestions');
    const suggestions = suggestionsBox.children;
    for (let i = 0; i < suggestions.length; i++) {
        suggestions[i].style.backgroundColor = i === activeSuggestionIndex ? 'var(--bg-hover)' : '';
    }
}

// --- Link preview functions ---
// Fetches a link preview for a given URL.
async function fetchLinkPreview(url) {
    try {
        const response = await fetch(`/link-preview?url=${encodeURIComponent(url)}`);
        if (!response.ok) {
            throw new Error('Link preview failed');
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching link preview:', error);
        return null;
    }
}

// Creates the HTML for a link preview.
function createLinkPreview(data) {
    if (!data || !data.title) return '';
    return `
        <div class="link-preview">
            ${data.image ? `<img src="${data.image}" alt="Preview" class="link-preview-image">` : ''}
            <div class="link-preview-content">
                <div class="link-preview-title">${data.title}</div>
                <div class="link-preview-description">${data.description || ''}</div>
                <div class="link-preview-url">${data.url}</div>
            </div>
        </div>
    `;
}

// Renders link previews in a given text.
async function renderLinkPreviews(text, container) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = text.match(urlRegex);

    if (urls) {
        for (const url of urls) {
            const preview = await fetchLinkPreview(url);
            if (preview) {
                const previewHtml = createLinkPreview(preview);
                container.innerHTML += previewHtml;
            }
        }
    }
}


// Loads the profile data for the user.
async function loadProfileData() {
    const profileIdentifier = getUserIdFromUrl();
    if (!profileIdentifier) {
        displayProfileError("No user ID or username provided in the URL.");
        return;
    }

    document.getElementById('profile-loading').classList.remove('hidden');
    document.getElementById('profile-content').classList.add('hidden');
    document.getElementById('profile-error').classList.add('hidden');

    try {
        const params = new URLSearchParams(window.location.search);
        const url = params.has('id') ? `/user/${profileIdentifier}` : `/user/by-username/${profileIdentifier}`;
        const response = await fetch(url);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: `Error ${response.status}` }));
            throw new Error(errorData.error || errorData.message || `Failed to load profile: ${response.status}`);
        }
        const profileData = await response.json();

        profileUserId = profileData.id;
        console.log(profileData)
        renderProfileData(profileData);

        document.getElementById('profile-loading').classList.add('hidden');
        document.getElementById('profile-content').classList.remove('hidden');

    } catch (error) {
        console.error("Failed to load profile data:", error);
        displayProfileError(error.message);
    }
}

// Renders the profile data on the page.
function renderProfileData(profile) {
    avatarContainer.innerHTML = '';
    const avatarElement = createProfileImage(profile.photo, profile.displayName, "profile-avatar", "text-5xl");
    avatarContainer.appendChild(avatarElement);

    const bannerImage = document.getElementById('banner-image');
    const bannerContainer = document.getElementById('banner-container');
    const profileHeader = bannerContainer.querySelector('.profile-header');

    if (profile.banner && profile.banner !== '/default-banner.png') {
        bannerImage.src = profile.banner;
        bannerImage.classList.remove('hidden');
        profileHeader.classList.add('hidden');
    } else {
        bannerImage.classList.add('hidden');
        profileHeader.classList.remove('hidden');
    }

    document.getElementById('profile-display-name').textContent = escapeHtml(profile.displayName);
    document.getElementById('profile-username').textContent = `@${escapeHtml(profile.username)}`;
    document.getElementById('profile-joined-date').textContent = `Joined on ${formatDate(profile.createdAt)}`;
    document.getElementById('profile-credibility').textContent = `Credibility: ${profile.credibility}`;
    if (profile.displayCountry && profile.country) {
        document.getElementById('profile-country').textContent = `From ${profile.country}`;
    } else {
        document.getElementById('profile-country').textContent = '';
    }

    const descriptionView = document.getElementById('profile-description-view');
    const descriptionEditInput = document.getElementById('profile-description-edit');
    descriptionView.textContent = profile.description || 'No description provided.';
    descriptionEditInput.value = profile.description || '';

    const editProfileButton = document.getElementById('edit-profile-button');
    const editControlsContainer = document.getElementById('edit-controls-container');
    const changeDisplayNameButton = document.getElementById('change-display-name');
    const changeUsernameButton = document.getElementById('change-username');

    if (currentUser && currentUser.id === profile.id) {
        editProfileButton.classList.remove('hidden');
        editProfileButton.addEventListener('click', toggleEditMode);

        document.getElementById('edit-description-button').onclick = () => {
            descriptionView.classList.add('hidden');
            document.getElementById('edit-description-button').classList.add('hidden');
            document.getElementById('edit-description-form').classList.remove('hidden');
            descriptionEditInput.focus();
        };

        document.getElementById('profile-picture-input-profile-page').addEventListener('change', handleProfilePictureSelect);
        document.getElementById('banner-picture-input').addEventListener('change', handleBannerPictureSelect);

    } else {
        editProfileButton.classList.add('hidden');
        editControlsContainer.classList.add('hidden');

        const friendRequestContainer = document.getElementById('friend-request-container');
        if (currentUser && currentUser.id !== profile.id) {
            fetch(`/friend-request/status/${profile.id}`)
                .then(response => response.json())
                .then(data => {
                    friendRequestContainer.innerHTML = '';
                    if (data.status === 'none') {
                        const addFriendBtn = document.createElement('button');
                        addFriendBtn.id = 'add-friend-btn';
                        addFriendBtn.className = 'button-primary w-full';
                        addFriendBtn.textContent = 'Add Friend';
                        addFriendBtn.onclick = async () => {
                            try {
                                const response = await fetch('/friend-request', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ recipientId: profile.id })
                                });
                                if (response.ok) {
                                    loadProfileData();
                                } else {
                                    const errorData = await response.json();
                                    alert(errorData.error);
                                }
                            } catch (error) {
                                console.error('Error sending friend request:', error);
                            }
                        };
                        friendRequestContainer.appendChild(addFriendBtn);
                    } else if (data.status === 'sent') {
                        const sentRequestBtn = document.createElement('button');
                        sentRequestBtn.className = 'button-secondary w-full';
                        sentRequestBtn.textContent = 'Request Sent';
                        sentRequestBtn.onclick = async () => {
                            try {
                                const response = await fetch(`/friend-request/${profile.id}`, {
                                    method: 'DELETE'
                                });
                                if (response.ok) {
                                    loadProfileData();
                                } else {
                                    const errorData = await response.json();
                                    alert(errorData.error);
                                }
                            } catch (error) {
                                console.error('Error cancelling friend request:', error);
                            }
                        };
                        friendRequestContainer.appendChild(sentRequestBtn);
                    } else if (data.status === 'received') {
                        const acceptRequestBtn = document.createElement('button');
                        acceptRequestBtn.className = 'button-primary w-full';
                        acceptRequestBtn.textContent = 'Accept Friend Request';
                        acceptRequestBtn.dataset.id = data.requestId;
                        acceptRequestBtn.addEventListener('click', async (e) => {
                            const requestId = e.target.dataset.id;
                            try {
                                const response = await fetch(`/friend-request/${requestId}/accept`, {
                                    method: 'PUT'
                                });
                                if (response.ok) {
                                    loadProfileData();
                                } else {
                                    const errorData = await response.json();
                                    alert(errorData.error || 'Failed to accept friend request.');
                                }
                            } catch (error) {
                                console.error('Error accepting friend request:', error);
                                alert('An error occurred while accepting the friend request.');
                            }
                        });
                        friendRequestContainer.appendChild(acceptRequestBtn);
                    } else if (data.status === 'friends') {
                        const friendsBtn = document.createElement('button');
                        friendsBtn.className = 'button-secondary w-full';
                        friendsBtn.textContent = 'Friends';
                        friendsBtn.disabled = true;
                        friendRequestContainer.appendChild(friendsBtn);
                    }
                });
        }
    }
}

// Displays an error message if the profile fails to load.
function displayProfileError(message) {
    document.getElementById('profile-loading').classList.add('hidden');
    document.getElementById('profile-content').classList.add('hidden');
    const errorElement = document.getElementById('profile-error');
    errorElement.classList.remove('hidden');
    errorElement.querySelector('p').textContent = message || "Could not load profile.";
}

// Saves the user's new description.
async function saveDescription() {
    const newDescription = document.getElementById('profile-description-edit').value;
    const saveButton = document.getElementById('save-description');
    saveButton.disabled = true;
    saveButton.textContent = 'Saving...';

    try {
        const response = await fetch('/user/description', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ description: newDescription })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Failed to save description.'}));
            throw new Error(errorData.error || errorData.message);
        }
        const result = await response.json();

        if (result.success) {
            document.getElementById('profile-description-view').textContent = result.description || 'No description provided.';
            if (currentUser && currentUser.id === profileUserId) {
                 currentUser.description = result.description;
            }
            cancelEditDescription();
        } else {
            alert('Failed to save description: ' + (result.error || 'Unknown error'));
        }

    } catch (error) {
        console.error("Error saving description:", error);
        alert('Error saving description: ' + error.message);
    } finally {
        saveButton.disabled = false;
        saveButton.textContent = 'Save Description';
    }
}

// Cancels the editing of the user's description.
function cancelEditDescription() {
    document.getElementById('edit-description-form').classList.add('hidden');
    document.getElementById('profile-description-view').classList.remove('hidden');
    document.getElementById('edit-description-button').classList.remove('hidden');
}

function toggleEditMode() {
    const editControlsContainer = document.getElementById('edit-controls-container');
    const editControls = document.querySelectorAll('.edit-control');
    const editProfileButton = document.getElementById('edit-profile-button');
    const isEditing = !editControlsContainer.classList.contains('hidden');

    if (isEditing) {
        editControlsContainer.classList.add('hidden');
        editControls.forEach(control => control.classList.add('hidden'));
        editProfileButton.textContent = 'Edit Profile';
    } else {
        editControlsContainer.classList.remove('hidden');
        editControls.forEach(control => control.classList.remove('hidden'));
        editProfileButton.textContent = 'Finish Editing';
    }
}

// Closes the image cropper modal.
function closeCropModal() {
    document.getElementById('crop-modal').classList.add('hidden');
    if (cropper) { cropper.destroy(); cropper = null; }
    if (bannerCropper) { bannerCropper.destroy(); bannerCropper = null; }
}

// Shows a notification message to the user.
function showNotification(message, type = 'info', duration = 3000) {
    const notificationContainerProfile = document.getElementById('notification-container');
    if (!notificationContainerProfile) {
        console.warn("Notification container not found on profile.html. Falling back to alert.");
        alert(`${type.toUpperCase()}: ${message}`);
        return;
    }

    const notificationId = `notif-profile-${Date.now()}`;
    const notification = document.createElement('div');
    notification.id = notificationId;
    notification.className = `notification notification-${type}`;

    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;
    notification.appendChild(messageSpan);

    const closeButton = document.createElement('button');
    closeButton.className = 'notification-close-btn';
    closeButton.innerHTML = '&times;';
    closeButton.onclick = () => {
        notification.classList.remove('notification-visible');
        setTimeout(() => notification.remove(), 300);
    };
    notification.appendChild(closeButton);

    notificationContainerProfile.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('notification-visible');
    }, 50);

    if (duration > 0) {
        setTimeout(() => {
            if (document.getElementById(notificationId)) {
                notification.classList.remove('notification-visible');
                setTimeout(() => notification.remove(), 300);
            }
        }, duration);
    }
}

// Closes the profile dropdown when clicking outside of it.
document.addEventListener('click', (e) => {
    const userProfileDropdown = document.getElementById('user-profile-dropdown-profile');
    const authSection = document.getElementById('auth-section-profile');
    if (authSection && userProfileDropdown &&
        !authSection.contains(e.target) &&
        !userProfileDropdown.contains(e.target)) {
        userProfileDropdown.classList.add('hidden');
    }
});

// Event listener for changing the display name.
document.getElementById('change-display-name').addEventListener('click', () => {
    document.getElementById('edit-display-name-form').classList.remove('hidden');
    document.getElementById('profile-display-name-edit').value = document.getElementById('profile-display-name').textContent;
    document.getElementById('profile-display-name-edit').focus();
});

// Event listener for canceling the display name change.
document.getElementById('cancel-edit-display-name').addEventListener('click', () => {
    document.getElementById('edit-display-name-form').classList.add('hidden');
});

// Event listener for saving the new display name.
document.getElementById('save-display-name').addEventListener('click', async () => {
    const newDisplayName = document.getElementById('profile-display-name-edit').value;
    if (newDisplayName.trim().length <= 0 || newDisplayName.trim().length > 50) {
        alert("Display name must be between 1 and 50 characters.")
        return
    }
    try {
        const response = await fetch('/user/displayName', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ displayName: newDisplayName })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Failed to save display name.'}));
            throw new Error(errorData.error || errorData.message);
        }
        const result = await response.json();

        if (result.success) {
            document.getElementById('profile-display-name').textContent = escapeHtml(result.displayName);
            if (currentUser && currentUser.id === profileUserId) {
                currentUser.displayName = result.displayName;
            }
            showNotification('Display name updated successfully!', 'success');
            document.getElementById('edit-display-name-form').classList.add('hidden');
        } else {
            alert('Failed to save display name: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error("Error saving display name:", error);
        alert('Error saving display name: ' + error.message);
    }
});

// Event listener for changing the username.
document.getElementById('change-username').addEventListener('click', () => {
    document.getElementById('edit-username-form').classList.remove('hidden');
    document.getElementById('profile-username-edit').value = document.getElementById('profile-username').textContent.substring(1);
    document.getElementById('profile-username-edit').focus();
});

// Event listener for canceling the username change.
document.getElementById('cancel-edit-username').addEventListener('click', () => {
    document.getElementById('edit-username-form').classList.add('hidden');
});

// Event listener for saving the new username.
document.getElementById('save-username').addEventListener('click', async () => {
    const newUsername = document.getElementById('profile-username-edit').value.toLowerCase();
    try {
        const response = await fetch('/user/username', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ username: newUsername })
        });

        const result = await response.json();

        if (response.ok && result.success) {
            document.getElementById('profile-username').textContent = `@${escapeHtml(result.username)}`;
            if (currentUser && currentUser.id === profileUserId) {
                currentUser.username = result.username;
            }
            showNotification('Username updated successfully!', 'success');
            document.getElementById('edit-username-form').classList.add('hidden');
        }else if (response.status == 409){
            showNotification('Username already taken', 'error')
            return
        } else {
            alert('Failed to save username: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error("Error saving username:", error);
        alert('Error saving username: ' + error.message);
    }
});

document.getElementById('save-description').addEventListener('click', saveDescription);
document.getElementById('cancel-edit-description').addEventListener('click', cancelEditDescription);

const descriptionEditInput = document.getElementById('profile-description-edit');
const descriptionCharCount = document.getElementById('description-char-count');

// Event listener for the description character count.
descriptionEditInput.addEventListener('input', () => {
    const currentLength = descriptionEditInput.value.length;
    const maxLength = descriptionEditInput.maxLength;
    descriptionCharCount.textContent = `${currentLength} / ${maxLength}`;
    if (currentLength >= maxLength) {
        descriptionCharCount.classList.add('text-red-500');
    } else {
        descriptionCharCount.classList.remove('text-red-500');
    }
});

// Event listener for saving the cropped image.
document.getElementById('crop-save').addEventListener('click', async () => {
    try {
        let result;
        if (bannerCropper) {
            console.log("Saving banner image...");
            result = await uploadCroppedBannerImage();
        } else {
            console.log("Saving profile picture...");
            result = await uploadCroppedImage();
        }

        if (result && result.success) {
            if (bannerCropper) {
                const bannerImage = document.getElementById('banner-image');
                const bannerContainer = document.getElementById('banner-container');
                const profileHeader = bannerContainer.querySelector('.profile-header');

                bannerImage.src = result.photo + '?t=' + Date.now();
                bannerImage.classList.remove('hidden');
                profileHeader.classList.add('hidden');

                if (currentUser && currentUser.id === profileUserId) {
                    currentUser.banner = result.photo;
                }
                showNotification('Banner image updated successfully!', 'success');
                closeCropModal();
                return;
            } else {
                if (currentUser && currentUser.id === profileUserId) {
                    currentUser.photo = result.photo;
                }
                const avatarContainer = document.getElementById('profile-avatar-container');
            }
            avatarContainer.innerHTML = '';
            const newAvatar = createProfileImage(result.photo, document.getElementById('profile-display-name').textContent, "profile-avatar", "text-5xl");
            avatarContainer.appendChild(newAvatar);

            if (currentUser && currentUser.id === profileUserId) {
                 updateProfilePageNav();
            }

            document.getElementById('crop-modal').classList.add('hidden');
            if (cropper) { cropper.destroy(); cropper = null; }
            showNotification('Profile picture updated successfully!', 'success');
        } else {
            showNotification(result.error || 'Failed to update profile picture.', 'error');
        }
    } catch (error) {
        console.error('Error updating profile picture:', error);
        showNotification(`Failed to update profile picture: ${error.message}`, 'error');
        document.getElementById('crop-modal').classList.add('hidden');
        if (cropper) { cropper.destroy(); cropper = null; }
    }
});

document.getElementById('crop-cancel').addEventListener('click', closeCropModal);
document.getElementById('crop-cancel-btn').addEventListener('click', closeCropModal);
window.addEventListener('resize', () => { if (cropper) cropper.resize(); });

// Initializes the page when the DOM is fully loaded.
// --- ALL RENDERING AND INTERACTION LOGIC FROM INDEX.HTML ---

function checkAndCollapsePost(articleElement) {
    const contentContainer = articleElement.querySelector('.post-content-container');
    if (!contentContainer) return;

    const threshold = 400;
    // Use a timeout to allow the browser to render the content and get the correct scrollHeight
    setTimeout(() => {
        if (contentContainer.scrollHeight > threshold) {
            articleElement.classList.add('post-collapsed');

            const seeMoreContainer = document.createElement('div');
            seeMoreContainer.className = 'see-more-btn-container';

            const seeMoreBtn = document.createElement('button');
            seeMoreBtn.className = 'see-more-btn text-blue-600 hover:underline';
            seeMoreBtn.textContent = 'See More';
            seeMoreBtn.onclick = (e) => {
                e.stopPropagation();
                if (articleElement.classList.contains('post-collapsed')) {
                    articleElement.classList.remove('post-collapsed');
                    seeMoreBtn.textContent = 'See Less';
                    seeMoreContainer.style.marginTop = '0';
                    seeMoreContainer.style.marginBottom = '1rem';
                } else {
                    articleElement.classList.add('post-collapsed');
                    seeMoreBtn.textContent = 'See More';
                    seeMoreContainer.style.marginTop = '-2rem';
                    seeMoreContainer.style.marginBottom = '0';
                }
            };

            seeMoreContainer.appendChild(seeMoreBtn);
            const postActionsDiv = articleElement.querySelector('.flex.items-center.space-x-4');
            if (postActionsDiv) {
                articleElement.insertBefore(seeMoreContainer, postActionsDiv);
            } else {
                articleElement.appendChild(seeMoreContainer);
            }
        }
    }, 0);
}

function renderPosts() {
    const container = document.getElementById('posts-container');
    const emptyState = document.getElementById('empty-state');

    const filteredPosts = posts.filter(post => {
        if (currentFilter === 'all') {
            return true;
        }
        return post.postType === currentFilter || (currentFilter === 'normal' && (!post.postType || post.postType === 'normal'));
    });

    if (filteredPosts.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        if (currentFilter !== 'all') {
            emptyState.querySelector('h3').textContent = `No posts found for "${currentFilter.charAt(0).toUpperCase() + currentFilter.slice(1)}"`;
            emptyState.querySelector('p').textContent = 'This user has not made any posts of this type yet.';
        } else {
            emptyState.querySelector('h3').textContent = 'No posts yet';
            emptyState.querySelector('p').textContent = "This user hasn't posted anything yet.";
        }
        return;
    }

    emptyState.classList.add('hidden');
    container.innerHTML = '';

    filteredPosts.forEach(post => {
        const article = document.createElement('article');
        article.className = 'rounded-lg shadow-md p-6 hover-lift fade-in';
        article.classList.add("cursor-pointer");
        article.onclick = () => {
            if (document.getElementById('single-post-container').classList.contains('hidden')) {
                let url = `/?post=${post.id}`;
                if (post.community) {
                    const communityId = typeof post.community === 'object' ? post.community._id : post.community;
                    if (communityId) {
                        url += `&community=${communityId}`;
                    }
                }
                const referrer = `&ref=profile&refId=${profileUserId}`;
                window.location.href = url + referrer;
            }
        };

        const postHeader = document.createElement('div');
        postHeader.className = 'flex items-center justify-between mb-4';

        const authorInfo = document.createElement('div');
        authorInfo.className = 'flex items-center space-x-3';

        const authorProfileLink = document.createElement('a');
        authorProfileLink.href = `/profile.html?id=${post.author.id}`;
        authorProfileLink.className = "flex items-center space-x-3 group";

        const postProfileImg = createProfileImage(post.author.photo, post.author.displayName, "w-10 h-10");
        authorProfileLink.appendChild(postProfileImg);

        const postHeaderInfo = document.createElement('div');
        postHeaderInfo.innerHTML = `
            <div class="font-medium text-gray-800 group-hover:underline">${escapeHtml(post.author.displayName)}</div>
            <div class="text-sm text-gray-500">${formatDate(post.createdAt)}</div>
        `;
        authorProfileLink.appendChild(postHeaderInfo);
        authorInfo.appendChild(authorProfileLink);
        postHeader.appendChild(authorInfo);

        const postActions = document.createElement('div');
        postActions.className = 'ml-auto relative';

        const menuButton = document.createElement('button');
        menuButton.className = 'text-gray-500 hover:text-gray-700 p-1 rounded-md hover:bg-gray-100 transition-colors';
        menuButton.innerHTML = `<svg id="menubuttons" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z"></path></svg>`;
        menuButton.onclick = (e) => {
            e.stopPropagation();
            toggleActionMenu('post', post.id);
        };
        postActions.appendChild(menuButton);

        const dropdownMenu = document.createElement('div');
        dropdownMenu.id = `post-action-menu-${post.id}`;
        dropdownMenu.className = 'hidden absolute right-0 mt-2 w-48 rounded-md shadow-lg py-1 z-20 post-action-menu';

        if (currentUser && currentUser.id === post.author.id) {
            const deleteButton = document.createElement('button');
            deleteButton.className = 'block w-full text-left px-4 py-2 text-sm profile-menu-item profile-menu-item-danger';
            deleteButton.innerHTML = `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                Delete Post
            `;
            deleteButton.onclick = (e) => {
                e.stopPropagation();
                confirmDeletePost(post.id);
                closeAllPostActionMenus();
            };
            dropdownMenu.appendChild(deleteButton);
        }
        if (currentUser && currentUser.id !== post.author.id) {
            const reportButton = document.createElement('button');
            reportButton.className = 'block w-full text-left px-4 py-2 text-sm hover:bg-gray-100';
            reportButton.innerHTML = `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 21v-4.25L16.25 3.5a2.121 2.121 0 013 3L6.25 19H3zm9-13l3 3"></path></svg>
                Report Post
            `;
            reportButton.onclick = (e) => {
                e.stopPropagation();
                openReportModal(post.id);
                closeAllPostActionMenus();
            };
            dropdownMenu.appendChild(reportButton);
        }

        if (currentUser && currentUser.id === post.author.id) {
            const createVoiceChannelButton = document.createElement('button');
            createVoiceChannelButton.className = 'block w-full text-left px-4 py-2 text-sm hover:bg-gray-100 create-vc-button';
            createVoiceChannelButton.innerHTML = `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.5 14.5a3.5 3.5 0 10-7 0v-1.586a1 1 0 01.293-.707l4.414-4.414a1 1 0 01.707-.293H15.5V14.5zM12 18a4 4 0 100-8 4 4 0 000 8z"></path></svg>
                Create Voice Channel
            `;
            createVoiceChannelButton.onclick = (e) => {
                e.stopPropagation();
                createVoiceChannel('post', post.id);
                closeAllPostActionMenus();
            };
            dropdownMenu.appendChild(createVoiceChannelButton);
        }

        if (dropdownMenu.hasChildNodes()) {
            postActions.appendChild(dropdownMenu);
            postHeader.appendChild(postActions);
        }

        const postTagsContainer = document.createElement('div');
        postTagsContainer.className = 'mb-2';

        if (post.postType && post.postType !== 'normal') {
            const typeBadge = document.createElement('span');
            typeBadge.className = `inline-block rounded-full px-3 py-1 text-xs font-semibold`;
            let badgeColor = 'bg-gray-200 text-gray-700';
            if (post.postType === 'question') badgeColor = 'bg-blue-100 text-blue-700';
            else if (post.postType === 'guide') badgeColor = 'bg-green-100 text-green-700';
            else if (post.postType === 'poll') badgeColor = 'bg-purple-100 text-purple-700';
            typeBadge.classList.add(...badgeColor.split(' '));
            typeBadge.textContent = post.postType.charAt(0).toUpperCase() + post.postType.slice(1);
            postTagsContainer.appendChild(typeBadge);
        }

        const postContentElement = document.createElement('div');
        postContentElement.className = 'post-content-container';
        const postTitleHtml = `<h2 class="text-xl font-bold mb-3">${escapeHtml(post.title)}</h2>`;
        postContentElement.innerHTML = postTitleHtml;

        const postTextParagraph = document.createElement('p');
        postTextParagraph.className = "text-gray-700 mb-6 whitespace-pre-wrap";

        const content = post.content;
        postTextParagraph.innerHTML = escapeHtml(content, true);
        postContentElement.appendChild(postTextParagraph);

        if (post.attachments && post.attachments.length > 0) {
            const imageAttachments = post.attachments.filter(a => a.fileType === 'image');
            const videoAttachments = post.attachments.filter(a => a.fileType === 'video');

            const firstImageIndex = post.attachments.findIndex(a => a.fileType === 'image');
            const firstVideoIndex = post.attachments.findIndex(a => a.fileType === 'video');

            const attachmentsContainer = document.createElement('div');

            const createImageSlideshow = () => {
                if (imageAttachments.length > 0) {
                    const imageSlideshowContainer = document.createElement('div');
                    imageSlideshowContainer.className = 'mt-4 mb-4 relative';
                    if (imageAttachments.length > 1) {
                        imageSlideshowContainer.className += ' flex overflow-x-auto space-x-2 pr-4 slideshow-scrollbar';
                    }
                    imageAttachments.forEach((attachment, index) => {
                        const attachmentWrapper = document.createElement('div');
                        attachmentWrapper.className = imageAttachments.length > 1 ? 'w-1/2 flex-shrink-0' : 'w-full';
                        const img = document.createElement('img');
                        img.src = attachment.url;
                        img.className = 'w-full h-full object-cover rounded cursor-pointer';
                        img.onclick = (e) => {
                            e.stopPropagation();
                            const imageUrls = imageAttachments.map(a => a.url);
                            openLightbox(imageUrls, index);
                        };
                        attachmentWrapper.appendChild(img);
                        imageSlideshowContainer.appendChild(attachmentWrapper);
                    });
                    attachmentsContainer.appendChild(imageSlideshowContainer);
                }
            };

            const createVideoSlideshow = () => {
                if (videoAttachments.length > 0) {
                    const videoSlideshowContainer = document.createElement('div');
                    videoSlideshowContainer.className = 'mt-4 mb-4 relative';
                    if (videoAttachments.length > 1) {
                        videoSlideshowContainer.className += ' flex overflow-x-auto space-x-2 pr-4 slideshow-scrollbar';
                    }
                    videoAttachments.forEach(attachment => {
                        const attachmentWrapper = document.createElement('div');
                        attachmentWrapper.className = videoAttachments.length > 1 ? 'w-1/2 flex-shrink-0' : 'w-full';
                        const videoWrapper = document.createElement('div');
                        videoWrapper.style.width = '100%';
                        videoWrapper.style.overflow = 'hidden';
                        videoWrapper.onclick = (e) => e.stopPropagation();
                        const video = document.createElement('video');
                        video.className = 'w-full h-auto object-cover rounded post-video';
                        video.controls = true;
                        video.setAttribute('playsinline', '');
                        video.setAttribute('loop', '');
                        video.muted = true;
                        const source = document.createElement('source');
                        source.src = attachment.url;
                        source.type = 'video/mp4';
                        video.appendChild(source);
                        video.innerHTML += 'Your browser does not support the video tag.';
                        videoWrapper.appendChild(video);
                        attachmentWrapper.appendChild(videoWrapper);
                        videoSlideshowContainer.appendChild(attachmentWrapper);
                    });
                    attachmentsContainer.appendChild(videoSlideshowContainer);
                }
            };

            if (firstImageIndex !== -1 && (firstVideoIndex === -1 || firstImageIndex < firstVideoIndex)) {
                createImageSlideshow();
                createVideoSlideshow();
            } else {
                createVideoSlideshow();
                createImageSlideshow();
            }

            postContentElement.appendChild(attachmentsContainer);
        }

        if (post.postType === 'poll' && post.pollOptions && post.pollOptions.length > 0) {
            const pollContainer = document.createElement('div');
            pollContainer.className = 'mb-4 p-4 border rounded-lg';
            pollContainer.id = `poll-${post.id}`;
            pollContainer.onclick = (e) => e.stopPropagation();

            const currentUserVote = post.usersWhoVoted && currentUser ? post.usersWhoVoted.find(vote => vote.userId === currentUser.id) : null;

            post.pollOptions.forEach((option, index) => {
                const optionDiv = document.createElement('div');
                optionDiv.className = 'mb-2';

                const totalVotes = post.pollOptions.reduce((sum, opt) => sum + (opt.votes || 0), 0);
                const percentage = totalVotes > 0 ? ((option.votes || 0) / totalVotes * 100).toFixed(1) : 0;

                let buttonClass = "w-full text-left p-2 rounded-md transition-colors flex justify-between items-center text-sm";
                let votedIndicator = '';
                let isDisabled = !currentUser;

                if (currentUserVote && currentUserVote.optionIndex === index) {
                    buttonClass += ' selected-poll-option';
                    votedIndicator = '<span class="text-xs font-semibold ml-2">(Your Vote)</span>';
                }

                if (currentUser) {
                     buttonClass += ' themed-hover-bg';
                }


                optionDiv.innerHTML = `
                    <button
                        onclick="event.stopPropagation(); voteInPoll('${post.id}', ${index})"
                        class="${buttonClass}"
                        data-option-index="${index}"
                        ${isDisabled ? 'disabled' : ''}
                        ${!currentUser ? 'title="Sign in to vote"' : 'title="Click to vote or change your vote"'} >
                        <span>${escapeHtml(option.option)} ${votedIndicator}</span>
                        <span class="text-xs text-gray-500 vote-count">${option.votes || 0} votes (${percentage}%)</span>
                    </button>
                    <div class="h-2 rounded-full mt-1 overflow-hidden poll-progress-track">
                        <div class="h-full transition-all duration-300 poll-progress-fill" style="width: ${percentage}%;"></div>
                    </div>
                `;
                pollContainer.appendChild(optionDiv);
            });
            postContentElement.appendChild(pollContainer);
        }

        article.appendChild(postHeader);
        if (postTagsContainer.hasChildNodes()) {
            article.appendChild(postTagsContainer);
        }
        article.appendChild(postContentElement);

        const linkPreviewsContainer = document.createElement('div');
        linkPreviewsContainer.className = 'link-previews';
        article.appendChild(linkPreviewsContainer);

        if (post.voiceChannel) {
            const voiceChannelElement = createVoiceChannelElement(post);
            if (voiceChannelElement) article.appendChild(voiceChannelElement);
        }

        if (post.linkPreview && post.linkPreview.url) {
            const preview = post.linkPreview;
            const previewContainer = document.createElement('a');
            previewContainer.href = preview.url;
            previewContainer.target = '_blank';
            previewContainer.rel = 'noopener noreferrer';
            previewContainer.className = 'flex items-center border rounded-lg overflow-hidden my-2 text-sm';
            previewContainer.style.textDecoration = 'none';
            previewContainer.onclick = (e) => e.stopPropagation();

            let imageHtml = '';
            if (preview.image) {
                imageHtml = `<img src="${escapeHtml(preview.image)}" alt="Preview" class="w-16 h-16 sm:w-20 sm:h-20 object-cover flex-shrink-0">`;
            }

            previewContainer.innerHTML = `
                ${imageHtml}
                <div class="p-2 overflow-hidden">
                    <div class="font-bold truncate">${escapeHtml(preview.title || '')}</div>
                    <div class="text-gray-600 text-xs truncate">${escapeHtml(preview.description || '')}</div>
                </div>
            `;
            linkPreviewsContainer.appendChild(previewContainer);
        } else {
            renderLinkPreviews(post.content, linkPreviewsContainer);
        }

        const postActionsDiv = document.createElement('div');
        postActionsDiv.className = 'flex items-center space-x-4 text-sm text-gray-500 mt-2 mb-4 pb-2';

        const likeButtonPost = document.createElement('button');
        likeButtonPost.className = `like-button flex items-center space-x-1 ${post.isLiked ? 'like-button-active' : ''}`;
        likeButtonPost.innerHTML = `
            <svg class="w-5 h-5 fill-current" viewBox="0 0 24 24">
                <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
            </svg>
        <span id="post-like-count-${post.id}">${post.likes || 0} Likes</span>
        `;
        likeButtonPost.onclick = (e) => {
            e.stopPropagation();
            toggleLike('post', post.id);
        };
        postActionsDiv.appendChild(likeButtonPost);

        const commentCountSpan = document.createElement('span');
        commentCountSpan.className = 'flex items-center space-x-1';
        const totalComments = countAllComments(post.comments);
        commentCountSpan.innerHTML = `
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path></svg>
            <span class="comment-count">${totalComments} Comments</span>
        `;
        postActionsDiv.appendChild(commentCountSpan);

        article.appendChild(postActionsDiv);

        container.appendChild(article);
        checkAndCollapsePost(article);
    });

    setupVideoObserver();
}

function renderCommentTree(comments, parentElement, postId, depth) {
    comments.forEach(comment => {
        const commentWrapper = document.createElement('div');
        commentWrapper.className = `comment-wrapper mt-3 pl-${depth * 2}`;

        const commentDiv = document.createElement('div');
        commentDiv.className = 'flex items-start space-x-3 bg-gray-50 p-3 rounded-lg shadow-sm';

        const commentBody = document.createElement('div');
        commentBody.className = 'flex-1 overflow-hidden';

        const commentAuthorProfileLink = document.createElement('a');
        commentAuthorProfileLink.href = `/profile.html?id=${comment.author.id}`;
        commentAuthorProfileLink.className = "shrink-0 group";

        const commentProfileImg = createProfileImage(comment.author.photo, comment.author.displayName, "w-8 h-8");
        commentAuthorProfileLink.appendChild(commentProfileImg);
        commentDiv.appendChild(commentAuthorProfileLink);

        const commentAuthorNameLink = document.createElement('a');
        commentAuthorNameLink.href = `/profile.html?id=${comment.author.id}`;
        commentAuthorNameLink.className = "font-medium text-gray-800 hover:underline";
        commentAuthorNameLink.textContent = escapeHtml(comment.author.displayName);

        const commentHeader = document.createElement('div');
        commentHeader.className = 'flex items-center space-x-2 mb-1';
        commentHeader.appendChild(commentAuthorNameLink);

        const commentTimestamp = document.createElement('span');
        commentTimestamp.className = "text-sm text-gray-500";
        commentTimestamp.textContent = formatDate(comment.createdAt);
        commentHeader.appendChild(commentTimestamp);
        commentBody.appendChild(commentHeader);

        if (comment.replyingTo && comment.replyingTo.username) {
            const replyingToText = document.createElement('p');
            replyingToText.className = 'text-xs text-gray-500 mb-1';
            if (comment.replyingTo.username === "Reply deleted") {
                 replyingToText.innerHTML = `Replying to: <span class="font-medium text-gray-600 italic">${escapeHtml(comment.replyingTo.username)}</span>`;
            } else {
                 replyingToText.innerHTML = `
                    Replying to:
                    <a href="/profile.html?id=${comment.replyingTo.id}" class="text-blue-600 hover:underline font-medium">
                        @${escapeHtml(comment.replyingTo.username)}
                    </a>
                `;
            }
            commentBody.appendChild(replyingToText);
        }

        const commentText = document.createElement('p');
        commentText.className = "text-gray-700 whitespace-pre-wrap break-all";

        if (comment.content.length > 300) {
            const seeMoreContainer = document.createElement('div');
            seeMoreContainer.className = `see-more-container ${depth === 0 ? 'comment-see-more' : 'reply-see-more'}`;

            const fullContent = document.createElement('p');
            fullContent.className = 'text-gray-700 whitespace-pre-wrap break-all';
            fullContent.innerHTML = escapeHtml(comment.content, true);

            seeMoreContainer.appendChild(fullContent);

            const seeMoreBtn = document.createElement('button');
            seeMoreBtn.className = 'see-more-btn text-blue-600 hover:underline';
            seeMoreBtn.textContent = 'See More';
            seeMoreBtn.onclick = () => {
                if (seeMoreContainer.classList.contains('expanded')) {
                    seeMoreContainer.classList.remove('expanded');
                    seeMoreBtn.textContent = 'See More';
                } else {
                    seeMoreContainer.classList.add('expanded');
                    seeMoreBtn.textContent = 'See Less';
                }
            };
            commentBody.appendChild(seeMoreContainer);
            commentBody.appendChild(seeMoreBtn);
        } else {
            commentText.innerHTML = escapeHtml(comment.content, true);
            commentBody.appendChild(commentText);
        }

        if (comment.linkPreview && comment.linkPreview.url) {
            const preview = comment.linkPreview;
            const previewContainer = document.createElement('a');
            previewContainer.href = preview.url;
            previewContainer.target = '_blank';
            previewContainer.rel = 'noopener noreferrer';
            previewContainer.className = 'flex items-center border rounded-lg overflow-hidden my-2 text-sm';
            previewContainer.style.textDecoration = 'none';
            previewContainer.onclick = (e) => e.stopPropagation();

            let imageHtml = '';
            if (preview.image) {
                imageHtml = `<img src="${escapeHtml(preview.image)}" alt="Preview" class="w-16 h-16 sm:w-20 sm:h-20 object-cover flex-shrink-0">`;
            }

            previewContainer.innerHTML = `
                ${imageHtml}
                <div class="p-2 overflow-hidden">
                    <div class="font-bold truncate">${escapeHtml(preview.title || '')}</div>
                    <div class="text-gray-600 text-xs truncate">${escapeHtml(preview.description || '')}</div>
                </div>
            `;
            commentBody.appendChild(previewContainer);
        }

        const commentActionsDiv = document.createElement('div');
        commentActionsDiv.className = 'comment-actions flex items-center space-x-3 text-xs text-gray-500 mt-2';

        const likeButtonComment = document.createElement('button');
        likeButtonComment.className = `like-button flex items-center space-x-1 ${comment.isLiked ? 'like-button-active' : ''}`;
        likeButtonComment.innerHTML = `
            <svg class="w-4 h-4 fill-current" viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></svg>
            <span id="comment-like-count-${comment.id}">${comment.likes || 0}</span>
        `;
        likeButtonComment.onclick = () => toggleLike('comment', comment.id);
        commentActionsDiv.appendChild(likeButtonComment);

        if (currentUser) {
            const replyButton = document.createElement('button');
            replyButton.className = 'hover:text-blue-600 font-medium';
            replyButton.textContent = 'Reply';
            replyButton.onclick = () => toggleReplyForm(comment.id, postId);
            commentActionsDiv.appendChild(replyButton);
        }
        commentBody.appendChild(commentActionsDiv);

        const commentMenuButton = document.createElement('button');
        commentMenuButton.className = 'comment-menu-button text-gray-500 hover:text-gray-700 p-1 rounded-md hover:bg-gray-100 transition-colors';
        commentMenuButton.innerHTML = `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z"></path></svg>`;
        commentMenuButton.onclick = (e) => {
            e.stopPropagation();
            toggleActionMenu('comment', comment.id);
        };

        const commentActions = document.createElement('div');
        commentActions.className = 'ml-auto relative';
        commentActions.appendChild(commentMenuButton);

        const dropdownMenu = document.createElement('div');
        dropdownMenu.id = `comment-action-menu-${comment.id}`;
        dropdownMenu.className = 'hidden absolute right-0 mt-2 min-w-max rounded-md shadow-lg py-1 z-20 comment-action-menu';
        dropdownMenu.style.backgroundColor = 'var(--dropdown-bg)';

        if (currentUser && currentUser.id === comment.author.id) {
            const deleteButton = document.createElement('button');
            deleteButton.className = 'block w-full text-left px-4 py-2 text-sm profile-menu-item profile-menu-item-danger';
            deleteButton.innerHTML = `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                Delete
            `;
            deleteButton.onclick = (e) => {
                e.stopPropagation();
                confirmDeleteComment(comment.id, postId, !comment.parentComment);
                closeAllCommentActionMenus();
            };
            dropdownMenu.appendChild(deleteButton);
        }

        if (currentUser && currentUser.id !== comment.author.id) {
            const reportButton = document.createElement('button');
            reportButton.className = 'block w-full text-left px-4 py-2 text-sm hover:bg-gray-100';
            reportButton.innerHTML = `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 21v-4.25L16.25 3.5a2.121 2.121 0 013 3L6.25 19H3zm9-13l3 3"></path></svg>
                Report
            `;
            reportButton.onclick = (e) => {
                e.stopPropagation();
                openReportModal(null, comment.id);
                closeAllCommentActionMenus();
            };
            dropdownMenu.appendChild(reportButton);
        }

        if (currentUser && currentUser.id === comment.author.id) {
            const createVoiceChannelButton = document.createElement('button');
            createVoiceChannelButton.className = 'block w-full text-left px-4 py-2 text-sm hover:bg-gray-100 create-vc-button';
            createVoiceChannelButton.innerHTML = `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.5 14.5a3.5 3.5 0 10-7 0v-1.586a1 1 0 01.293-.707l4.414-4.414a1 1 0 01.707-.293H15.5V14.5zM12 18a4 4 0 100-8 4 4 0 000 8z"></path></svg>
                Create Voice Channel
            `;
            createVoiceChannelButton.onclick = (e) => {
                e.stopPropagation();
                createVoiceChannel('comment', comment.id);
                closeAllCommentActionMenus();
            };
            dropdownMenu.appendChild(createVoiceChannelButton);
        }

        if (dropdownMenu.hasChildNodes()) {
            commentActions.appendChild(dropdownMenu);
            commentHeader.appendChild(commentActions);
        }

        const replyFormContainerId = `reply-form-container-${comment.id}`;
        const replyFormContainer = document.createElement('div');
        replyFormContainer.id = replyFormContainerId;
        replyFormContainer.className = 'reply-form hidden mt-2';
        commentBody.appendChild(replyFormContainer);

        commentDiv.appendChild(commentBody);
        commentWrapper.appendChild(commentDiv);

        if (comment.replies && comment.replies.length > 0) {
            renderCommentTree(comment.replies, commentWrapper, postId, depth + 1);
        }

        parentElement.appendChild(commentWrapper);
    });
}

function toggleReplyForm(commentId, postId) {
    const containerId = `reply-form-container-${commentId}`;
    const container = document.getElementById(containerId);
    if (!container) return;

    const existingForm = container.querySelector('textarea');
    if (existingForm) {
        container.classList.toggle('hidden');
        if (!container.classList.contains('hidden')) {
            container.querySelector('textarea').focus();
        }
    } else {
        let commentData = null;
        const post = posts.find(p => p.id === postId);
        if (post) {
            function findCommentById(comments, id) {
                for (const c of comments) {
                    if (c.id === id) return c;
                    if (c.replies && c.replies.length > 0) {
                        const foundInReply = findCommentById(c.replies, id);
                        if (foundInReply) return foundInReply;
                    }
                }
                return null;
            }
            commentData = findCommentById(post.comments, commentId);
        }

        if (!commentData) {
            console.error("Could not find comment data for ID:", commentId);
            return;
        }

        container.innerHTML = `
            <p class="text-xs text-gray-500 mb-1">
                Replying to:
                <a href="/profile.html?id=${commentData.author.id}" class="text-blue-600 hover:underline font-medium">
                    ${escapeHtml(commentData.author.displayName)}
                </a>
            </p>
            <textarea id="reply-textarea-${commentId}" placeholder="Write a reply..." rows="2" maxlength="1000"
                      class="w-full px-3 py-2 text-sm rounded-lg resize-none focus:outline-none focus:ring-1" onkeyup="handleMention(this)"></textarea>
            <div class="flex justify-between items-center mt-1">
                <span class="text-xs text-gray-500">0 / 1000</span>
                <div class="flex justify-end space-x-2">
                    <button onclick="document.getElementById('${containerId}').classList.add('hidden');"
                            class="button-cancel-reply px-3 py-1 text-xs rounded-md">Cancel</button>
                    <button onclick="addCommentOrReply('${postId}', '${commentId}')"
                            class="button-submit-reply px-3 py-1 text-xs rounded-md">Reply</button>
                </div>
            </div>
        `;
        container.classList.remove('hidden');
        const textarea = container.querySelector('textarea');
        const charCountSpan = container.querySelector('span');
        textarea.addEventListener('input', () => {
            const currentLength = textarea.value.length;
            const maxLength = textarea.maxLength;
            charCountSpan.textContent = `${currentLength} / ${maxLength}`;
            if (currentLength >= maxLength) {
                charCountSpan.classList.add('text-red-500');
            } else {
                charCountSpan.classList.remove('text-red-500');
            }
        });
        textarea.focus();
    }
}

async function addCommentOrReply(postId, parentCommentId = null) {
    const textareaId = parentCommentId ? `reply-textarea-${parentCommentId}` : `comment-textarea-${postId}`;
    const textarea = document.getElementById(textareaId);
    if (!textarea) {
        console.error("Textarea not found:", textareaId);
        return;
    }
    const content = textarea.value.trim();

    if (!content) return;

    try {
        let url, body;
        if (parentCommentId) {
            url = `/comments/${parentCommentId}/replies`;
            body = JSON.stringify({ content });
        } else {
            url = `/posts/${postId}/comments`;
            body = JSON.stringify({ content });
        }

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: body
        });

        if (response.ok) {
            const newComment = await response.json();
            const postIndex = posts.findIndex(p => p.id === postId);
            if (postIndex !== -1) {
                if (parentCommentId) {
                    const findAndAddReply = (comments) => {
                        for (const comment of comments) {
                            if (comment.id === parentCommentId) {
                                if (!comment.replies) {
                                    comment.replies = [];
                                }
                                newComment.replyingTo = {
                                    id: comment.author.id,
                                    username: comment.author.username
                                };
                                comment.replies.push(newComment);
                                return true;
                            }
                            if (comment.replies && findAndAddReply(comment.replies)) {
                                return true;
                            }
                        }
                        return false;
                    };
                    findAndAddReply(posts[postIndex].comments);
                } else {
                    posts[postIndex].comments.push(newComment);
                }
            }

            renderSinglePost(postId);
            textarea.value = '';
            showNotification("Comment added successfully.", "success");

            const post = posts.find(p => p.id === postId);
            if (post) {
                const commentCountSpan = document.querySelector(`#post-${postId} .comment-count`);
                if (commentCountSpan) {
                    const totalComments = countAllComments(post.comments);
                    commentCountSpan.textContent = `${totalComments} Comments`;
                }
            }
        } else {
            const errorData = await response.json();
            showNotification(`Failed to add ${parentCommentId ? 'reply' : 'comment'}: ${errorData.error || 'Server error'}`, 'error');
        }
    } catch (error) {
        console.error(`Failed to add ${parentCommentId ? 'reply' : 'comment'}:`, error);
        showNotification(`An error occurred while adding ${parentCommentId ? 'reply' : 'comment'}. Please try again.`, 'error');
    }
}

function toggleActionMenu(type, id) {
    const singlePostContainer = document.getElementById('single-post-container');
    const isSinglePostView = !singlePostContainer.classList.contains('hidden');

    let context = document;
    if (isSinglePostView) {
        // When in single post view, the menu ID might have a '-single' suffix
        // but let's try a more robust querySelector within the visible container.
        context = singlePostContainer;
    }

    const menuId = `${type}-action-menu-${id}`;
    // A special case for single post view on the profile page where the ID is different
    const singlePostMenuId = `post-action-menu-single-${id}`;

    let menu = context.querySelector(`#${menuId}`);
    if (!menu && isSinglePostView) {
         menu = context.querySelector(`#${singlePostMenuId}`);
    }

    if (menu) {
        const isHidden = menu.classList.contains('hidden');

        // Close all menus first if we are about to open a new one.
        if (isHidden) {
            closeAllActionMenus();
        }

        // Now, toggle the specific menu.
        menu.classList.toggle('hidden');
    }
}

function closeAllActionMenus() {
    document.querySelectorAll('.post-action-menu, .comment-action-menu').forEach(menu => {
        menu.classList.add('hidden');
    });
}

document.addEventListener('click', (event) => {
    if (!event.target.closest('.post-menu-button') && !event.target.closest('.post-action-menu') &&
        !event.target.closest('.comment-menu-button') && !event.target.closest('.comment-action-menu')) {
        closeAllActionMenus();
    }
});

const reportModalOverlay = document.getElementById('report-modal-overlay');
const reportForm = document.getElementById('report-form');
const reportPostIdInput = document.getElementById('report-post-id');
const reportReasonTypeSelect = document.getElementById('report-reason-type');
const reportReasonOtherContainer = document.getElementById('report-reason-other-container');
const reportReasonOtherInput = document.getElementById('report-reason-other');
const reportDescriptionInput = document.getElementById('report-description');

function openReportModal(postId) {
    if (!currentUser) {
        showNotification("Please sign in to report posts.", "warning");
        return;
    }
    reportPostIdInput.value = postId;
    reportReasonTypeSelect.value = 'not_type';
    reportReasonOtherContainer.classList.add('hidden');
    reportReasonOtherInput.value = '';
    reportDescriptionInput.value = '';
    reportModalOverlay.classList.remove('hidden');
}

function closeReportModal() {
    reportModalOverlay.classList.add('hidden');
}

reportReasonTypeSelect.addEventListener('change', () => {
    if (reportReasonTypeSelect.value === 'other') {
        reportReasonOtherContainer.classList.remove('hidden');
    } else {
        reportReasonOtherContainer.classList.add('hidden');
    }
});

document.getElementById('report-modal-cancel-btn').addEventListener('click', closeReportModal);
reportModalOverlay.addEventListener('click', (event) => {
    if (event.target === reportModalOverlay) {
        closeReportModal();
    }
});

reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const postId = reportPostIdInput.value;
    let reasonType = reportReasonTypeSelect.value;
    let reasonDetails = reportDescriptionInput.value.trim();

    if (reasonType === 'other') {
        const otherReason = reportReasonOtherInput.value.trim();
        if (!otherReason) {
            showNotification('Please specify the reason if "Other" is selected.', 'warning');
            return;
        }
        reasonType = `other: ${otherReason}`;
    }

    try {
        const response = await fetch(`/posts/${postId}/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reasonType, reasonDetails })
        });
        if (response.ok) {
            showNotification('Post reported successfully. Thank you for your feedback.', 'success');
            closeReportModal();
        } else {
            const errorData = await response.json().catch(() => ({ error: 'Failed to submit report.' }));
            showNotification(`Error: ${errorData.error}`, 'error');
        }
    } catch (error) {
        console.error('Failed to submit report:', error);
        showNotification('An error occurred while submitting the report.', 'error');
    }
});

async function voteInPoll(postId, optionIndex) {
    event.stopPropagation();
    if (!currentUser) {
        showNotification("Please sign in to vote.", "warning");
        return;
    }
    try {
        const response = await fetch(`/posts/${postId}/vote`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ optionIndex })
        });

        if (response.ok) {
            const updatedPost = await response.json();
            const postIndex = posts.findIndex(p => p.id === postId);
            if (postIndex !== -1) {
                posts[postIndex].pollOptions = updatedPost.pollOptions;
                posts[postIndex].usersWhoVoted = updatedPost.usersWhoVoted;
            }

            const singlePostContainer = document.getElementById('single-post-container');
            const container = singlePostContainer.classList.contains('hidden') ? document : singlePostContainer;
            const pollContainer = container.querySelector(`#poll-${postId}`);

            if (pollContainer) {
                const localPost = posts[postIndex];
                const currentUserVote = localPost.usersWhoVoted && currentUser ? localPost.usersWhoVoted.find(vote => vote.userId === currentUser.id) : null;
                const totalVotes = localPost.pollOptions.reduce((sum, opt) => sum + (opt.votes || 0), 0);

                localPost.pollOptions.forEach((option, index) => {
                    const optionButton = pollContainer.querySelector(`button[data-option-index="${index}"]`);
                    if (optionButton) {
                        pollContainer.querySelectorAll('button').forEach(btn => btn.classList.remove('selected-poll-option'));

                        let buttonClass = "w-full text-left p-2 rounded-md transition-colors flex justify-between items-center text-sm themed-hover-bg";
                        let votedIndicator = '';

                        if (currentUserVote && currentUserVote.optionIndex === index) {
                            buttonClass += ' selected-poll-option';
                            votedIndicator = '<span class="text-xs font-semibold ml-2">(Your Vote)</span>';
                        }

                        optionButton.className = buttonClass;

                        const optionTextSpan = optionButton.querySelector('span:first-child');
                        if (optionTextSpan) {
                            optionTextSpan.innerHTML = `${escapeHtml(option.option)} ${votedIndicator}`;
                        }

                        const voteCountSpan = optionButton.querySelector('.vote-count');
                        const percentage = totalVotes > 0 ? ((option.votes || 0) / totalVotes * 100).toFixed(1) : 0;
                        if (voteCountSpan) {
                            voteCountSpan.textContent = `${option.votes || 0} votes (${percentage}%)`;
                        }

                        const progressBarFill = optionButton.nextElementSibling.querySelector('.poll-progress-fill');
                        if (progressBarFill) {
                            progressBarFill.style.width = `${percentage}%`;
                        }
                    }
                });
            }
            showNotification('Vote cast successfully!', 'success');
        } else {
            const errorData = await response.json().catch(() => ({ error: 'Failed to cast vote.' }));
            showNotification(`Error: ${errorData.error}`, 'error');
        }
    } catch (error) {
        console.error('Error voting in poll:', error);
        showNotification('An error occurred while casting your vote.', 'error');
    }
}

async function toggleLike(type, id) {
    if (!currentUser) {
        showNotification("Please sign in to like content.", "warning");
        return;
    }

    let url;
    if (type === 'post') {
        url = `/posts/${id}/like`;
    } else if (type === 'comment') {
        url = `/comments/${id}/like`;
    } else {
        return;
    }

    try {
        const response = await fetch(url, { method: 'POST' });
        if (response.ok) {
            const result = await response.json();

            if (type === 'post') {
                const postIndex = posts.findIndex(p => p.id === id);
                if (postIndex !== -1) {
                    posts[postIndex].likes = result.likesCount;
                    posts[postIndex].isLiked = result.isLiked;
                }
            } else if (type === 'comment') {
                function findAndUpdateComment(commentsArray, commentId, newLikesCount, newIsLiked) {
                    for (let i = 0; i < commentsArray.length; i++) {
                        let currentComment = commentsArray[i];
                        if (currentComment.id === commentId) {
                            currentComment.likes = newLikesCount;
                            currentComment.isLiked = newIsLiked;
                            return true;
                        }
                        if (currentComment.replies && currentComment.replies.length > 0) {
                            if (findAndUpdateComment(currentComment.replies, commentId, newLikesCount, newIsLiked)) {
                                return true;
                            }
                        }
                    }
                    return false;
                }
                for (let i = 0; i < posts.length; i++) {
                    if (posts[i].comments && findAndUpdateComment(posts[i].comments, id, result.likesCount, result.isLiked)) {
                        break;
                    }
                }
            }

            const likeCountSpan = document.getElementById(`${type}-like-count-${id}`);
            const likeButton = likeCountSpan ? likeCountSpan.parentElement : null;

            if (likeCountSpan) {
                likeCountSpan.textContent = type === 'post' ? `${result.likesCount} Likes` : `${result.likesCount}`;
            }

            if (likeButton) {
                if (result.isLiked) {
                    likeButton.classList.add('like-button-active');
                } else {
                    likeButton.classList.remove('like-button-active');
                }
            }

            const singlePostContainer = document.getElementById('single-post-container');
            if (!singlePostContainer.classList.contains('hidden')) {
                const post = posts.find(p => p.id === id);
                const likeCountSpan = document.querySelector(`#single-post-container #post-like-count-${id}`);
                const likeButton = likeCountSpan ? likeCountSpan.parentElement : null;

                if (likeCountSpan) {
                    likeCountSpan.textContent = `${post.likes} Likes`;
                }

                if (likeButton) {
                    if (post.isLiked) {
                        likeButton.classList.add('like-button-active');
                    } else {
                        likeButton.classList.remove('like-button-active');
                    }
                }
            }

        } else {
            const errorData = await response.json().catch(() => ({error: "Unknown error"}));
            showNotification(`Failed to update like for ${type}: ${errorData.error}`, 'error');
        }
    } catch (error) {
        console.error(`Error toggling like for ${type} ${id}:`, error);
        showNotification(`Error updating like for ${type}. Please try again.`, 'error');
    }
}

async function confirmDeletePost(postId) {
    if (!currentUser) return;

    const postToDelete = posts.find(p => p.id === postId);
    if (!postToDelete || postToDelete.author.id !== currentUser.id) {
        showNotification("You are not authorized to delete this post or the post was not found.", "error");
        return;
    }

    showConfirmationDialog(
        "Are you sure you want to delete this post? This will also delete all associated comments and replies.",
        async () => {
            try {
                const response = await fetch(`/posts/${postId}`, {
                    method: 'DELETE',
                });

                if (response.ok) {
                    await loadProfileContent();
                    showNotification("Post deleted successfully.", "success");
                } else {
                    const errorData = await response.json().catch(() => ({error: "Server error"}));
                    showNotification(`Failed to delete post: ${errorData.error}`, 'error');
                }
            } catch (error) {
                console.error('Error deleting post:', error);
                showNotification('An error occurred while trying to delete the post.', 'error');
            }
        },
        () => {
            showNotification("Delete operation cancelled.", "info", 2000);
        },
        "Delete Post",
        "Delete",
        "Cancel"
    );
}

async function confirmDeleteComment(commentId, isTopLevelComment) {
    if (!currentUser) return;

    let message = "Are you sure you want to delete this reply? This action cannot be undone.";
    if (isTopLevelComment) {
        message = "Are you sure you want to delete this comment? This will also delete all its replies. This action cannot be undone.";
    }

    showConfirmationDialog(
        message,
        async () => {
            try {
                const response = await fetch(`/comments/${commentId}`, {
                    method: 'DELETE',
                });

                if (response.ok) {
                    const post = posts.find(p => p.comments.some(c => c.id === commentId) ||
                                             p.comments.some(c => c.replies && c.replies.some(r => r.id === commentId)));

                    if (post) {
                        const removeComment = (comments) => {
                            for (let i = 0; i < comments.length; i++) {
                                if (comments[i].id === commentId) {
                                    comments.splice(i, 1);
                                    return true;
                                }
                                if (comments[i].replies && removeComment(comments[i].replies)) {
                                    return true;
                                }
                            }
                            return false;
                        };
                        removeComment(post.comments);
                        renderSinglePost(post.id);
                        const commentCountSpan = document.querySelector(`#post-${post.id} .comment-count`);
                        if (commentCountSpan) {
                            const totalComments = countAllComments(post.comments);
                            commentCountSpan.textContent = `${totalComments} Comments`;
                        }
                    }
                    showNotification("Comment/reply deleted successfully.", "success");
                } else {
                    const errorData = await response.json().catch(() => ({error: "Server error"}));
                    showNotification(`Failed to delete comment/reply: ${errorData.error}`, 'error');
                }
            } catch (error) {
                console.error('Error deleting comment/reply:', error);
                showNotification('An error occurred while trying to delete the comment/reply.', 'error');
            }
        },
        () => {
        },
        "Delete Comment/Reply",
        "Delete",
        "Cancel"
    );
}


function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' at ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

const confirmationModalOverlay = document.getElementById('confirmation-modal-overlay');
const confirmationModalElement = document.getElementById('confirmation-modal');
const confirmationModalMessage = document.getElementById('confirmation-modal-message');
const confirmationModalTitle = document.getElementById('confirmation-modal-title');
const confirmBtn = document.getElementById('confirmation-modal-confirm-btn');
const cancelBtn = document.getElementById('confirmation-modal-cancel-btn');

let currentOnConfirm = null;
let currentOnCancel = null;

function showConfirmationDialog(message, onConfirmCallback, onCancelCallback, title = "Confirm Action", confirmText = "Confirm", cancelText = "Cancel") {
    if (!confirmationModalOverlay || !confirmationModalMessage || !confirmBtn || !cancelBtn || !confirmationModalTitle) {
        console.error("Confirmation modal elements not found.");
        if (confirm(message)) {
            if (onConfirmCallback) onConfirmCallback();
        } else {
            if (onCancelCallback) onCancelCallback();
        }
        return;
    }

    confirmationModalMessage.textContent = message;
    confirmationModalTitle.textContent = title;
    confirmBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;

    currentOnConfirm = onConfirmCallback;
    currentOnCancel = onCancelCallback;

    confirmationModalOverlay.classList.remove('hidden');
}

function closeConfirmationDialog() {
    confirmationModalOverlay.classList.add('hidden');
    currentOnConfirm = null;
    currentOnCancel = null;
}

confirmBtn.addEventListener('click', () => {
    if (currentOnConfirm) {
        currentOnConfirm();
    }
    closeConfirmationDialog();
});

cancelBtn.addEventListener('click', () => {
    if (currentOnCancel) {
        currentOnCancel();
    }
    closeConfirmationDialog();
});

confirmationModalOverlay.addEventListener('click', (event) => {
    if (event.target === confirmationModalOverlay) {
         if (currentOnCancel) {
            currentOnCancel();
        }
        closeConfirmationDialog();
    }
});

function showMainFeed() {
    document.getElementById('posts-container').classList.remove('hidden');
    document.getElementById('single-post-container').classList.add('hidden');
    document.getElementById('profile-content').classList.remove('hidden');
}

function countAllComments(comments) {
    let count = comments.length;
    for (const comment of comments) {
        if (comment.replies) {
            count += countAllComments(comment.replies);
        }
    }
    return count;
}

async function renderSinglePost(postId) {
    const post = posts.find(p => p.id === postId);
    if (!post) {
        showMainFeed();
        return;
    }
    currentSinglePostId = postId;

    document.getElementById('posts-container').classList.add('hidden');
    document.getElementById('profile-controls').classList.add('hidden');
    document.getElementById('profile-content').classList.add('hidden');

    const container = document.getElementById('single-post-container');
    container.innerHTML = '';
    container.classList.remove('hidden');

    const article = document.createElement('article');
    article.className = 'rounded-lg shadow-md p-6';

    const backButton = document.createElement('button');
    backButton.className = 'back-to-posts-btn text-blue-600 hover:underline mb-4';
    backButton.innerHTML = '&larr; Back to profile';
    backButton.onclick = () => {
        const url = new URL(window.location);
        url.searchParams.delete('post');
        history.pushState({ postId: null }, "", url);
        showMainFeed();
        renderPosts();
    };
    container.appendChild(backButton);

    const postHeader = document.createElement('div');
    postHeader.className = 'flex items-center space-x-3 mb-4';

    const authorProfileLink = document.createElement('a');
    authorProfileLink.href = `/profile.html?id=${post.author.id}`;
    authorProfileLink.className = "flex items-center space-x-3 group flex-grow";

    const postProfileImg = createProfileImage(post.author.photo, post.author.displayName, "w-10 h-10");
    authorProfileLink.appendChild(postProfileImg);

    const postHeaderInfo = document.createElement('div');
    postHeaderInfo.innerHTML = `
        <div class="font-medium text-gray-800 group-hover:underline">${escapeHtml(post.author.displayName)}</div>
        <div class="text-sm text-gray-500">${formatDate(post.createdAt)}</div>
    `;
    authorProfileLink.appendChild(postHeaderInfo);
    postHeader.appendChild(authorProfileLink);

    const postActionsMenu = document.createElement('div');
    postActionsMenu.className = 'ml-auto relative';

    const menuButton = document.createElement('button');
    menuButton.className = 'text-gray-500 hover:text-gray-700 p-1 rounded-md hover:bg-gray-100 transition-colors';
    menuButton.innerHTML = `<svg id="menubuttons" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z"></path></svg>`;
    menuButton.onclick = (e) => {
        e.stopPropagation();
        toggleActionMenu('post', post.id);
    };
    postActionsMenu.appendChild(menuButton);

    const dropdownMenu = document.createElement('div');
    dropdownMenu.id = `post-action-menu-single-${post.id}`;
    dropdownMenu.className = 'hidden absolute right-0 mt-2 w-48 rounded-md shadow-lg py-1 z-20 post-action-menu';

    if (currentUser && currentUser.id === post.author.id) {
        const deleteButton = document.createElement('button');
        deleteButton.className = 'block w-full text-left px-4 py-2 text-sm profile-menu-item profile-menu-item-danger';
        deleteButton.innerHTML = `
            <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            Delete Post
        `;
        deleteButton.onclick = () => {
            confirmDeletePost(post.id);
            closeAllPostActionMenus();
        };
        dropdownMenu.appendChild(deleteButton);
    }

    if (currentUser && currentUser.id !== post.author.id) {
        const reportButton = document.createElement('button');
        reportButton.className = 'block w-full text-left px-4 py-2 text-sm hover:bg-gray-100';
        reportButton.innerHTML = `
            <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 21v-4.25L16.25 3.5a2.121 2.121 0 013 3L6.25 19H3zm9-13l3 3"></path></svg>
            Report Post
        `;
        reportButton.onclick = () => {
            openReportModal(post.id);
            closeAllPostActionMenus();
        };
        dropdownMenu.appendChild(reportButton);
    }

    if (dropdownMenu.hasChildNodes()) {
        postActionsMenu.appendChild(dropdownMenu);
        postHeader.appendChild(postActionsMenu);
    }

    const postTagsContainer = document.createElement('div');
    postTagsContainer.className = 'mb-2';

    if (post.postType && post.postType !== 'normal') {
        const typeBadge = document.createElement('span');
        typeBadge.className = `inline-block rounded-full px-3 py-1 text-xs font-semibold`;
        let badgeColor = 'bg-gray-200 text-gray-700';
        if (post.postType === 'question') badgeColor = 'bg-blue-100 text-blue-700';
        else if (post.postType === 'guide') badgeColor = 'bg-green-100 text-green-700';
        else if (post.postType === 'poll') badgeColor = 'bg-purple-100 text-purple-700';
        typeBadge.classList.add(...badgeColor.split(' '));
        typeBadge.textContent = post.postType.charAt(0).toUpperCase() + post.postType.slice(1);
        postTagsContainer.appendChild(typeBadge);
    }

    const postContentElement = document.createElement('div');
    const postTitleHtml = `<h2 class="text-xl font-bold mb-3">${escapeHtml(post.title)}</h2>`;
    postContentElement.innerHTML = postTitleHtml;

    const postTextParagraph = document.createElement('p');
    postTextParagraph.className = "text-gray-700 mb-4 whitespace-pre-wrap";

    const seeMoreContainer = document.createElement('div');
    seeMoreContainer.className = 'see-more-container post-see-more';

    const fullContent = document.createElement('p');
    fullContent.className = 'text-gray-700 mb-4 whitespace-pre-wrap';
    fullContent.innerHTML = escapeHtml(post.content, true);

    seeMoreContainer.appendChild(fullContent);
    if (post.content.length > 500) {
        const seeMoreBtn = document.createElement('button');
        seeMoreBtn.className = 'see-more-btn text-blue-600 hover:underline';
        seeMoreBtn.textContent = 'See More';
        seeMoreBtn.onclick = () => {
            if (seeMoreContainer.classList.contains('expanded')) {
                seeMoreContainer.classList.remove('expanded');
                seeMoreBtn.textContent = 'See More';
            } else {
                seeMoreContainer.classList.add('expanded');
                seeMoreBtn.textContent = 'See Less';
            }
        };
        postContentElement.appendChild(seeMoreContainer);
        postContentElement.appendChild(seeMoreBtn);
    } else {
        postTextParagraph.innerHTML = escapeHtml(post.content, true);
        postContentElement.appendChild(postTextParagraph);
    }

    if (post.attachments && post.attachments.length > 0) {
        // ... attachment logic ...
    }

    if (post.postType === 'poll' && post.pollOptions && post.pollOptions.length > 0) {
        // ... poll logic ...
    }
    const commentsSection = document.createElement('div');
    commentsSection.className = 'border-t pt-4';

    const commentsHeader = document.createElement('h3');
    commentsHeader.className = 'font-semibold mb-3';
    commentsHeader.style = 'color: var(--bg-primary)'
    const totalComments = countAllComments(post.comments);
    commentsHeader.textContent = `Comments (${totalComments})`;
    commentsSection.appendChild(commentsHeader);

    if (currentUser) {
        const commentFormContainer = document.createElement('div');
        commentFormContainer.className = 'mb-4';
        const textarea = document.createElement('textarea');
        textarea.id = `comment-textarea-${post.id}`;
        textarea.placeholder = "Add a comment...";
        textarea.rows = 2;
        textarea.maxLength = 1000;
        textarea.className = "w-full px-3 py-2 rounded-lg resize-none focus:outline-none focus:ring-2";
        textarea.onkeyup = () => handleMention(textarea);

        const charCountSpan = document.createElement('span');
        charCountSpan.className = 'text-sm text-gray-500';
        charCountSpan.textContent = '0 / 1000';

        const button = document.createElement('button');
        button.onclick = () => addCommentOrReply(post.id);
        button.className = "button-submit-comment mt-2 px-4 py-2 rounded-lg font-medium transition-colors";
        button.textContent = "Add Comment";

        textarea.addEventListener('input', () => {
            const currentLength = textarea.value.length;
            const maxLength = textarea.maxLength;
            charCountSpan.textContent = `${currentLength} / ${maxLength}`;
            if (currentLength >= maxLength) {
                charCountSpan.classList.add('text-red-500');
            } else {
                charCountSpan.classList.remove('text-red-500');
            }
        });

        const bottomDiv = document.createElement('div');
        bottomDiv.className = 'flex justify-between items-center';
        bottomDiv.appendChild(charCountSpan);
        bottomDiv.appendChild(button);

        commentFormContainer.appendChild(textarea);
        commentFormContainer.appendChild(bottomDiv);
        commentsSection.appendChild(commentFormContainer);
    }

    const commentsContainer = document.createElement('div');
    commentsContainer.className = 'space-y-3';
    renderCommentTree(post.comments, commentsContainer, post.id, 0);

    commentsSection.appendChild(commentsContainer);

    article.appendChild(postHeader);
    if (postTagsContainer.hasChildNodes()) {
        article.appendChild(postTagsContainer);
    }
    article.appendChild(postContentElement);

    if (post.linkPreview && post.linkPreview.url) {
        // ... link preview logic ...
    }

    const postActionsDiv = document.createElement('div');
    postActionsDiv.className = 'flex items-center flex-wrap gap-x-4 gap-y-2 text-sm text-gray-500 mt-2 mb-4 pb-2';

    const likeButtonPost = document.createElement('button');
    likeButtonPost.className = `like-button flex items-center space-x-1 ${post.isLiked ? 'like-button-active' : ''}`;
    likeButtonPost.innerHTML = `
        <svg class="w-5 h-5 fill-current" viewBox="0 0 24 24">
            <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
        </svg>
    <span id="post-like-count-${post.id}">${post.likes || 0} Likes</span>
    `;
    likeButtonPost.onclick = () => toggleLike('post', post.id);
    postActionsDiv.appendChild(likeButtonPost);

    if (post.voiceChannel) {
        const vcContainer = document.createElement('div');
        vcContainer.className = 'mt-2 p-2 rounded-lg flex items-center justify-between';
        vcContainer.style.backgroundColor = 'var(--voice-channel-bg)';

        vcContainer.innerHTML = `
            <div class="flex items-center space-x-2">
                <svg class="w-5 h-5" style="color: var(--voice-channel-icon-color);" fill="currentColor" viewBox="0 0 20 20"><path d="M10 12a2 2 0 100-4 2 2 0 000 4z"></path><path fill-rule="evenodd" d="M.458 10C3.732 5.943 7.523 4 10 4c2.477 0 6.268 1.943 9.542 6-.273.333-.553.658-.838.979l-.28.322a14.98 14.98 0 01-1.37 1.328C15.093 19.34 11.857 20 10 20c-1.857 0-5.093-.66-7.054-2.371A14.98 14.98 0 011.278 11.3L1.001 11a.45.45 0 01-.543-1zM10 16a6 6 0 100-12 6 6 0 000 12z" clip-rule="evenodd"></path></svg>
                <span class="font-medium text-sm">Voice Channel Active</span>
            </div>
        `;
        const joinButton = document.createElement('button');
        joinButton.className = 'button-primary text-xs px-3 py-1';
        joinButton.textContent = 'Join';
        joinButton.onclick = (e) => {
            e.stopPropagation();
            window.open(`/voice-channel.html?id=${post.voiceChannel._id}`, '_blank');
        };
        vcContainer.appendChild(joinButton);
        postActionsDiv.appendChild(vcContainer);
    } else if (currentUser) {
        const createVcButton = document.createElement('button');
        createVcButton.className = 'flex items-center space-x-1 hover:text-blue-600';
        createVcButton.innerHTML = `
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
            <span>Create VC</span>
        `;
        createVcButton.onclick = (e) => {
            e.stopPropagation();
            createVoiceChannel('post', post.id);
        };
        postActionsDiv.appendChild(createVcButton);
    }

    article.appendChild(postActionsDiv);
    article.appendChild(commentsSection);

    container.appendChild(article);

    setupVideoObserver();
}

window.onpopstate = function(event) {
    if (event.state && event.state.postId) {
        renderSinglePost(event.state.postId);
    } else {
        showMainFeed();
    }
};

window.addEventListener('pageshow', function(event) {
    if (event.persisted) {
        console.log('Page restored from bfcache. Reloading content.');
        loadProfileContent();
    }
});

const lightboxModal = document.getElementById('lightbox-modal');
const lightboxImage = document.getElementById('lightbox-image');
const lightboxClose = document.getElementById('lightbox-close');
const lightboxPrev = document.getElementById('lightbox-prev');
const lightboxNext = document.getElementById('lightbox-next');

let currentImageIndex = 0;
let currentImageList = [];

function openLightbox(images, index) {
    currentImageList = images;
    currentImageIndex = index;
    updateLightboxImage();
    lightboxModal.classList.remove('hidden');
}

function closeLightbox() {
    lightboxModal.classList.add('hidden');
}

function updateLightboxImage() {
    lightboxImage.src = currentImageList[currentImageIndex];
}

function showPrevImage() {
    currentImageIndex = (currentImageIndex - 1 + currentImageList.length) % currentImageList.length;
    updateLightboxImage();
}

function showNextImage() {
    currentImageIndex = (currentImageIndex + 1) % currentImageList.length;
    updateLightboxImage();
}

lightboxClose.addEventListener('click', closeLightbox);
lightboxPrev.addEventListener('click', showPrevImage);
lightboxNext.addEventListener('click', showNextImage);

document.addEventListener('keydown', (e) => {
    if (lightboxModal.classList.contains('hidden')) return;
    if (e.key === 'Escape') closeLightbox();
    if (e.key === 'ArrowLeft') showPrevImage();
    if (e.key === 'ArrowRight') showNextImage();
});

let videoObserver;
let currentlyPlayingVideo = null;

function setupVideoObserver() {
    const options = {
        root: null,
        rootMargin: '0px',
        threshold: 0.8,
    };

    videoObserver = new IntersectionObserver(handleVideoIntersection, options);
    const videos = document.querySelectorAll('.post-video');
    videos.forEach(video => videoObserver.observe(video));
}

function handleVideoIntersection(entries, observer) {
    entries.forEach(entry => {
        const video = entry.target;
        if (entry.isIntersecting) {
            if (currentlyPlayingVideo && currentlyPlayingVideo !== video) {
                currentlyPlayingVideo.pause();
            }
            video.play().catch(e => console.error("Video play failed:", e));
            currentlyPlayingVideo = video;
        } else {
            video.pause();
            if (currentlyPlayingVideo === video) {
                currentlyPlayingVideo = null;
            }
        }
    });
}

async function loadProfileContent() {
    const userId = profileUserId;
    if (!userId) return;

    const contentType = document.querySelector('.filter-btn.active-filter-btn').dataset.contentType;
    const sortBy = document.getElementById('sort-by-select').value;
    const feedContainer = document.getElementById('posts-container');
    const emptyState = document.getElementById('empty-state');

    feedContainer.innerHTML = '<p class="text-center p-8">Loading content...</p>';
    emptyState.classList.add('hidden');

    try {
        const response = await fetch(`/user/${userId}/content?contentType=${contentType}&sortBy=${sortBy}`);
        if (!response.ok) {
            throw new Error('Failed to load content');
        }
        const content = await response.json();
        if (contentType === 'posts') {
            posts = content;
            renderPosts();
        } else {
            renderComments(content);
        }
    } catch (error) {
        console.error('Error loading user content:', error);
        feedContainer.innerHTML = '';
        emptyState.classList.remove('hidden');
        emptyState.querySelector('h3').textContent = 'Could not load content';
        emptyState.querySelector('p').textContent = 'There was an error fetching this user\'s content.';
    }
}

function renderComments(comments) {
    const container = document.getElementById('posts-container');
    container.innerHTML = '';
    const emptyState = document.getElementById('empty-state');
    if (comments.length === 0) {
        emptyState.classList.remove('hidden');
        emptyState.querySelector('h3').textContent = 'No Comments Found';
        emptyState.querySelector('p').textContent = 'This user has not made any comments.';
        return;
    }
    emptyState.classList.add('hidden');
    comments.forEach(comment => {
        const commentElement = createCommentElement(comment);
        container.appendChild(commentElement);
    });
}

function createCommentElement(comment) {
    const commentElement = document.createElement('div');
    commentElement.className = 'rounded-lg shadow-md p-4';
    commentElement.style.backgroundColor = 'var(--post-card-bg)';
    const postTitle = comment.post ? escapeHtml(comment.post.title) : '[Post deleted]';

    const commentContentHtml = escapeHtml(comment.content, true);

    commentElement.innerHTML = `
        <div class="text-sm text-gray-500">
            Commented on <strong>${postTitle}</strong>
        </div>
        <div class="mt-2 whitespace-pre-wrap">${commentContentHtml}</div>
        <div class="link-previews"></div>
        <div class="text-xs text-gray-400 mt-2">
            ${new Date(comment.createdAt).toLocaleString()} |
            ${comment.likes.length} likes
        </div>
    `;

    const linkPreviewsContainer = commentElement.querySelector('.link-previews');
    if (comment.linkPreview && comment.linkPreview.url) {
        const preview = comment.linkPreview;
        const previewContainer = document.createElement('a');
        previewContainer.href = preview.url;
        previewContainer.target = '_blank';
        previewContainer.rel = 'noopener noreferrer';
        previewContainer.className = 'flex items-center border rounded-lg overflow-hidden my-2 text-sm';
        previewContainer.style.textDecoration = 'none';
        previewContainer.onclick = (e) => e.stopPropagation();

        let imageHtml = '';
        if (preview.image) {
            imageHtml = `<img src="${escapeHtml(preview.image)}" alt="Preview" class="w-16 h-16 sm:w-20 sm:h-20 object-cover flex-shrink-0">`;
        }

        previewContainer.innerHTML = `
            ${imageHtml}
            <div class="p-2 overflow-hidden">
                <div class="font-bold truncate">${escapeHtml(preview.title || '')}</div>
                <div class="text-gray-600 text-xs truncate">${escapeHtml(preview.description || '')}</div>
            </div>
        `;
        linkPreviewsContainer.appendChild(previewContainer);
    } else {
        renderLinkPreviews(comment.content, linkPreviewsContainer);
    }

    return commentElement;
}

document.addEventListener('DOMContentLoaded', async () => {
    avatarContainer = document.getElementById('profile-avatar-container');
    await checkAuthStatusForProfilePage();

    if (currentUser) {
        socket.on('voice-channel-created', ({ itemType, itemId, voiceChannel }) => {
            if (itemType === 'post') {
                const postIndex = posts.findIndex(p => p.id === itemId);
                if (postIndex !== -1) {
                    posts[postIndex].voiceChannel = voiceChannel;
                    if (itemId === currentSinglePostId) {
                        renderSinglePost(itemId);
                    } else {
                        renderPosts();
                    }
                }
            }
        });

        socket.on('voice-channel-deleted', ({ channelId, postId, commentId }) => {
            let updatedPostId = null;

            // 1. Update local state
            if (postId) {
                const postIndex = posts.findIndex(p => p.id === postId || p._id === postId);
                if (postIndex !== -1) {
                    posts[postIndex].voiceChannel = null;
                    updatedPostId = posts[postIndex].id || posts[postIndex]._id;
                }
            } else if (commentId) {
                for (const post of posts) {
                    const comment = findComment(post.comments, commentId);
                    if (comment) {
                        comment.voiceChannel = null;
                        updatedPostId = post.id || post._id;
                        break;
                    }
                }
            }

            // 2. Update UI
            const singlePostContainer = document.getElementById('single-post-container');
            const isSinglePostView = !singlePostContainer.classList.contains('hidden');
            const currentSinglePostId = isSinglePostView ? singlePostContainer.querySelector('article')?.id.replace('post-card-', '') : null;

            if (isSinglePostView && updatedPostId === currentSinglePostId) {
                renderSinglePost(updatedPostId);
            } else {
                // For feeds or profile pages, directly manipulate the DOM.
                const vcElement = document.querySelector(`.voice-channel-container #voice-participants-${channelId}`);
                if (vcElement) {
                    const container = vcElement.closest('.voice-channel-container');
                    if (container) container.remove();
                }

                // Make the 'Create VC' button visible again.
                const cardId = postId ? `post-card-${postId}` : `comment-wrapper-${commentId}`;
                const cardElement = document.getElementById(cardId);
                if (cardElement) {
                    const dropdownMenu = cardElement.querySelector('.post-action-menu');
                    if (dropdownMenu) {
                        const createVoiceChannelButton = document.createElement('button');
                        createVoiceChannelButton.className = 'block w-full text-left px-4 py-2 text-sm hover:bg-gray-100 create-vc-button';
                        createVoiceChannelButton.innerHTML = `
                            <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.5 14.5a3.5 3.5 0 10-7 0v-1.586a1 1 0 01.293-.707l4.414-4.414a1 1 0 01.707-.293H15.5V14.5zM12 18a4 4 0 100-8 4 4 0 000 8z"></path></svg>
                            Create Voice Channel
                        `;
                        createVoiceChannelButton.onclick = (e) => {
                            e.stopPropagation();
                            createVoiceChannel('post', postId);
                            closeAllPostActionMenus();
                        };
                        dropdownMenu.appendChild(createVoiceChannelButton);
                    }
                }
            }
        });
    }

    await loadProfileData();
    loadProfileContent();

    document.getElementById('filter-posts-btn').addEventListener('click', () => {
        document.getElementById('filter-posts-btn').classList.add('active-filter-btn');
        document.getElementById('filter-comments-btn').classList.remove('active-filter-btn');
        loadProfileContent();
    });

    document.getElementById('filter-comments-btn').addEventListener('click', () => {
        document.getElementById('filter-comments-btn').classList.add('active-filter-btn');
        document.getElementById('filter-posts-btn').classList.remove('active-filter-btn');
        loadProfileContent();
    });

    document.getElementById('sort-by-select').addEventListener('change', loadProfileContent);
});