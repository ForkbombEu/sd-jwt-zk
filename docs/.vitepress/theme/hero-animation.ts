import type { AnimationItem } from 'lottie-web'

export async function mountForkbombAnimation(container?: HTMLElement) {
  if (!container || container.dataset.fbLottieMounted === 'true') return () => {}

  container.dataset.fbLottieMounted = 'true'

  const [{ default: lottie }, { default: animationData }] = await Promise.all([
    import('lottie-web/build/player/lottie_light.js'),
    import('./assets/forkbomb-animation.json'),
  ])

  if (!container.isConnected) return () => {}

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
  const animation: AnimationItem = lottie.loadAnimation({
    container,
    renderer: 'svg',
    loop: false,
    autoplay: false,
    animationData,
    rendererSettings: {
      preserveAspectRatio: 'xMidYMid meet',
      progressiveLoad: true,
    },
  })

  let ready = false
  let intersecting = false
  let complete = false

  const syncPlayback = () => {
    if (!ready) return

    if (reducedMotion.matches) {
      animation.goToAndStop(animation.totalFrames - 1, true)
      return
    }

    if (intersecting && !document.hidden && !complete) animation.play()
    else animation.pause()
  }

  const handleReady = () => {
    ready = true
    syncPlayback()
  }

  const handleComplete = () => {
    complete = true
  }

  const handleMotionChange = (event: MediaQueryListEvent) => {
    if (!event.matches) {
      complete = false
      animation.goToAndStop(0, true)
    }
    syncPlayback()
  }

  const observer = new IntersectionObserver(([entry]) => {
    intersecting = entry.isIntersecting
    syncPlayback()
  }, { threshold: 0.25 })

  animation.addEventListener('DOMLoaded', handleReady)
  animation.addEventListener('complete', handleComplete)
  reducedMotion.addEventListener('change', handleMotionChange)
  document.addEventListener('visibilitychange', syncPlayback)
  observer.observe(container)

  return () => {
    observer.disconnect()
    reducedMotion.removeEventListener('change', handleMotionChange)
    document.removeEventListener('visibilitychange', syncPlayback)
    animation.removeEventListener('DOMLoaded', handleReady)
    animation.removeEventListener('complete', handleComplete)
    animation.destroy()
    delete container.dataset.fbLottieMounted
  }
}
